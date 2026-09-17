"""Обезличивание текстов перед отправкой во внешний LLM.

Ядро выросло из скрипта обезличивания Telegram-выгрузок и обкатано в бою на
helpdesk-платформе. Ключевые свойства:

- запоминает каждую выполненную подстановку (реальное -> фейковое значение),
  что позволяет построить обратную карту и «дезанонимизировать» ответ модели
  перед показом оператору — замена строго ограничена картой;
- подстановки детерминированы (seed = SHA256 реального значения), поэтому
  одному человеку/компании всегда соответствует один и тот же фейк — без
  хранения какого-либо состояния между запросами;
- перед отправкой в LLM можно проверить текст на остатки реальных данных
  (leaks_in_text).

Режимы: "fake" (реалистичные подстановки — лучше для качества LLM, обратная
замена точная) и "placeholders" ([PHONE]/[EMAIL]/USER_1 — обратная замена
только для однозначных плейсхолдеров).
"""
from __future__ import annotations

import hashlib
import random
import re

# --- Регулярки для чувствительных фрагментов в текстах ------------------------------
RE_LINK = re.compile(r"(?:https?://|www\.|t\.me/)[^\s,;)\]}\u00bb\"'<>]+", re.IGNORECASE)
RE_EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
RE_PHONE_CANDIDATE = re.compile(r"\+?\d[\d\s\-()]{8,}\d")
RE_MENTION = re.compile(r"(?<![\w.@-])@[A-Za-z0-9_]{3,}")
# Хвост (?!\.\d+\.): tcpdump/procnet пишет адрес с портом через точку
# (5.141.102.236.30039) — такой IP матчится, порт остаётся как есть.
# Отсюда же защита от осколков длинных точечных цепочек (1.2.3.4.5.6 —
# не IP) и от склейки с хвостом-цифрой (192.168.0.66 не съедает 192.168.0.6).
RE_IP = re.compile(r"(?<!\d)(?<!\d\.)(\d{1,3}(?:\.\d{1,3}){3})(?!\d)(?!\.\d+\.)")
# голые домены (chat.example.tj): метки из латиницы/цифр/дефисов, последний
# сегмент — только буквы 2–14 (похоже на TLD); файловые расширения отсекает
# repl. "@" в lookbehind: домен сразу после @ — это часть e-mail (в т.ч.
# уже вставленного фейкового), его нельзя чистить повторной фазой.
RE_DOMAIN = re.compile(
    r"(?<![A-Za-z0-9_./\\@-])"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
    r"(?![A-Za-z0-9-])"
)
RE_WILDCARD_DOMAIN = re.compile(
    r"\*\."
    r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+"
    r"(?![A-Za-z0-9-])"
)
# расширения файлов, которые выглядят как домены, но ими не являются
FILE_EXTS = {
    "yml", "yaml", "py", "sh", "conf", "crt", "key", "log", "json", "xml", "txt",
    "md", "sql", "tar", "gz", "zip", "env", "ini", "service", "timer", "bak", "tmp",
    "png", "jpg", "jpeg", "gif", "csv", "xlsx", "doc", "docx", "pdf", "css", "js",
    "lock", "pid", "sock", "iso", "img", "deb", "rpm", "so", "bin", "exe", "apk",
    "ts", "tsx", "pyc", "woff", "woff2", "ttf", "pem", "cer", "der", "crl", "cfg",
    "plist", "mobileconfig", "icns", "map",
}
# «Кодовые» соседи: если латинское имя/ник вплотную к одному из этих символов —
# оно часть пути/команды/переменной (docker-compose, $var, /path/to, file.txt)
# и заменять его нельзя, иначе текст превращается в кашу.
CODE_BOUND = r"[A-Za-z0-9_./$=`<>|&*+{}~#\\-]"

# --- Словари для реалистичных подстановок (режим "fake") -----------------------------
MALE_NAMES = [
    "Александр", "Алексей", "Андрей", "Антон", "Аркадий", "Артём", "Борис", "Вадим",
    "Валентин", "Валерий", "Василий", "Виктор", "Виталий", "Владимир", "Владислав",
    "Вячеслав", "Геннадий", "Глеб", "Григорий", "Даниил", "Денис", "Дмитрий",
    "Евгений", "Егор", "Иван", "Игорь", "Илья", "Кирилл", "Константин", "Леонид",
    "Максим", "Марк", "Михаил", "Никита", "Николай", "Олег", "Павел", "Пётр",
    "Роман", "Руслан", "Семён", "Сергей", "Станислав", "Степан", "Тимур", "Фёдор",
    "Юрий", "Ярослав",
]
FEMALE_NAMES = [
    "Алина", "Алла", "Алёна", "Александра", "Анастасия", "Анна", "Валентина",
    "Валерия", "Вера", "Вероника", "Виктория", "Галина", "Дарья", "Евгения",
    "Екатерина", "Елена", "Елизавета", "Жанна", "Зинаида", "Инна", "Ирина",
    "Клавдия", "Кристина", "Ксения", "Лариса", "Лидия", "Любовь", "Людмила",
    "Маргарита", "Марина", "Мария", "Милана", "Надежда", "Наталья", "Нина",
    "Оксана", "Ольга", "Полина", "Раиса", "Светлана", "Софья", "Тамара",
    "Татьяна", "Ульяна", "Эльвира", "Юлия", "Яна",
]
SURNAMES_M = [
    "Соколов", "Морозов", "Волков", "Кузнецов", "Павлов", "Романов", "Гусев",
    "Крылов", "Максимов", "Захаров", "Белов", "Орлов", "Виноградов", "Коновалов",
    "Фролов", "Абрамов", "Николаев", "Гришин", "Дмитриев", "Киселёв", "Макаров",
    "Андреев", "Титов", "Фомин", "Черкасов", "Борисов", "Осипов", "Сидоров",
    "Матвеев", "Тарасов", "Владимиров", "Филиппов", "Игнатьев", "Комаров",
    "Прохоров", "Быков", "Жуков", "Воробьёв", "Воронов", "Соболев", "Лебедев",
    "Симонов", "Голубев", "Гордеев", "Дроздов", "Кононов", "Дементьев",
    "Логинов", "Сафонов", "Капустин", "Кириллов", "Панфилов", "Данилов",
    "Савельев", "Тихонов", "Казаков", "Афанасьев",
]
SURNAMES_F = [s + "а" for s in SURNAMES_M if not s.endswith("й")]
SURNAMES_N = [  # не склоняемые, пол не определяется
    "Бондарчук", "Кравчук", "Ткаченко", "Гончар", "Кушнир", "Лившиц", "Берг",
    "Гринберг", "Кантор", "Резник", "Шульц", "Ким", "Цой", "Пак", "Гуменюк",
    "Мельниченко", "Полищук", "Савченко", "Литвин", "Гнатюк",
]
ORG_WORDS_A = ["Северный", "Балтийский", "Утренний", "Ясный", "Стремительный", "Тихий"]
ORG_WORDS_B = ["Путь", "Дом", "Логистик", "Сервис", "Проект", "Контур", "Вектор", "Импульс"]
FAKE_DOMAINS = ["example.com", "example.org", "example.net"]

# для фейковых ников (латиница, стиль Telegram)
LAT_FIRST = [
    "alexey", "andrey", "anna", "artem", "denis", "dmitry", "elena", "ivan",
    "kirill", "marina", "natalia", "olga", "oleg", "pavel", "roman", "sergey",
    "svetlana", "tatiana", "victor", "yulia",
]
LAT_LAST = [
    "sokolov", "morozov", "volkov", "kuznetsov", "pavlov", "orlov", "lebedev",
    "makarov", "belov", "frolov", "popov", "zaitsev", "vinogradov", "sidorov",
]


def _is_nick(s: str) -> bool:
    """Ник, а не имя: латиница/цифры/подчёркивания, возможно с @."""
    return bool(re.fullmatch(r"@?[A-Za-z0-9_]{3,}", s)) and bool(re.search(r"[A-Za-z]", s))


def _phone_like(cand: str) -> bool:
    digits = sum(ch.isdigit() for ch in cand)
    has_separators = any(ch in " -()" for ch in cand)
    return (
        (cand.startswith("+") and 8 <= digits <= 14)
        or (has_separators and 10 <= digits <= 14)
        or 11 <= digits <= 13  # сплошные цифры, но не unixtime/даты (10 цифр)
    )


# детерминированный ГПСЧ живёт в validators (общий для всех модулей ядра);
# здесь — локальные алиасы, чтобы остальной код не менялся
from compass_llm_filter.core.validators import (  # noqa: E402
    det_rng as _det_rng, fake_digits as _fake_digits,
    inn_ok as _inn_ok, ogrn_ok as _ogrn_ok, snils_ok as _snils_ok,
)
from compass_llm_filter.core import ru_pii, secrets  # noqa: E402


def _ru_identifier(digits: str) -> bool:
    """Цифровая цепочка — валидный СНИЛС/ИНН/ОГРН(ИП): телефонная фаза её
    пропускает, заменой займётся ru_pii (фейк с валидной контрольной суммой,
    а не телефон)."""
    return _snils_ok(digits) or _inn_ok(digits) or _ogrn_ok(digits)


def _defer_to_ru_pii(cand: str) -> bool:
    """Кандидат телефонной фазы — СНИЛС/ИНН/ОГРН с валидной суммой или
    паспорт РФ (4 цифры, пробел, 6 цифр): пропускаем, заменит фаза ru_pii —
    иначе паспорт станет «телефоном»."""
    digits = "".join(ch for ch in cand if ch.isdigit())
    return _ru_identifier(digits) or re.fullmatch(r"\d{4} \d{6}", cand) is not None


def _is_domain_like(d: str) -> bool:
    tld = d.split(".")[-1]
    return 2 <= len(tld) <= 14 and tld.isalpha() and tld.lower() not in FILE_EXTS


class Anonymizer:
    """Обезличивание строк + обратная подстановка по накопленной карте.

    Порядок замен внутри текста: полные имена -> ники (всё через маркеры),
    затем поверх — ссылки/секреты/почты/@упоминания/домены/телефоны/
    RU-идентификаторы (карты, СНИЛС, ИНН, ОГРН, паспорта — после телефона,
    который валидные суммы пропускает)/IP, и только потом раскрытие маркеров.
    Так generic-замены не портят уже вставленные фейки и нет двойных подстановок.
    """

    def __init__(self, mode: str = "fake"):
        if mode not in ("fake", "placeholders"):
            raise ValueError(f"Unknown anonymization mode: {mode}")
        self.fake = mode == "fake"
        self.name_map: dict[str, str] = {}
        self._used_aliases: set[str] = set()
        self._substitutions: list[tuple[str, str]] = []  # (реальное, фейковое)
        self._secret_values: list[str] = []  # фейки секретов текущего sanitize_string
        self._phases = None
        self._leak_re = None
        self._leak_lat_re = None
        self.stats = {
            "names": 0, "links": 0, "emails": 0, "phones": 0,
            "mentions": 0, "ips": 0, "domains": 0,
            "cards": 0, "snils": 0, "inns": 0, "inns12": 0,
            "ogrns": 0, "ogrnips": 0, "passports": 0, "secrets": 0,
        }

    # --- регистрация известных сущностей (имена/компании) ---------------------------

    def register_entity(self, value: str, kind: str = "auto") -> str | None:
        """Зарегистрировать известное имя/название компании. Вернёт фейк или
        None, если значение не похоже на имя (мусор/цифры/слишком короткое).
        После регистрации все вхождения value в обезличиваемых текстах
        будут заменены."""
        if not isinstance(value, str):
            return None
        value = value.strip()
        if len(value) < 2 or not re.search(r"[А-Яа-яЁёA-Za-z]", value):
            return None
        if value in self.name_map:
            return self.name_map[value]
        if self.fake and (kind == "org" or
                          (kind == "auto" and re.match(
                              r"^(ООО|ОАО|ЗАО|ПАО|АО|ИП|ФГУП|ФГБУ|НКО|Фонд|Компания)\b",
                              value, re.IGNORECASE))):
            alias = self._register(value, self._fake_org(value))
        else:
            alias = self.alias_for_name(value)
        self._record(value, alias)
        return alias

    def _record(self, real: str, fake_value: str) -> None:
        self._substitutions.append((real, fake_value))

    def _secret_mark(self, fake_value: str) -> str:
        """Секрет -> маркер \x00sN\x00; финальный фейк подставится в конце
        sanitize_string. Без маркера последующие фазы видят уже вставленный
        фейк-пароль как e-mail local part (postgres://user:FAKE@host) или как
        Bearer-токен и маскируют повторно — цепочка подстановок ломает
        обратное восстановление."""
        self._secret_values.append(fake_value)
        return f"\x00s{len(self._secret_values) - 1}\x00"

    # --- карты соответствий ------------------------------------------------------------

    def _register(self, real: str, fake_value: str) -> str:
        self.name_map[real] = fake_value
        self._used_aliases.add(fake_value)
        self._phases = None  # карта изменилась — кэш нужно перестроить
        return fake_value

    def _guess_gender(self, first_word: str) -> str | None:
        if first_word in MALE_NAMES:
            return "m"
        if first_word in FEMALE_NAMES:
            return "f"
        if first_word.endswith(("а", "я")) and len(first_word) > 3:
            return "f"
        return None

    @staticmethod
    def _hits(fake_value: str, avoid) -> bool:
        """Фейк содержит чьё-то реальное имя (совпал с участником) — перегенерить."""
        return avoid is not None and any(r in fake_value for r in avoid)

    def _fake_org(self, name: str, avoid=None) -> str:
        for attempt in range(50):
            rng = _det_rng("org", name, attempt)
            fake_value = f"{rng.choice(ORG_WORDS_A)} {rng.choice(ORG_WORDS_B)}"
            if fake_value not in self._used_aliases and not self._hits(fake_value, avoid):
                return fake_value
        rng = _det_rng("org", name)
        return f"{rng.choice(ORG_WORDS_A)} {rng.choice(ORG_WORDS_B)}"

    def _fake_username(self, name: str, avoid=None) -> str:
        """Другой ник того же стиля: с/без @, с цифрами, если были в оригинале."""
        prefix = "@" if name.startswith("@") else ""
        for attempt in range(50):
            rng = _det_rng("nick", name.lower(), attempt)
            fake_value = f"{rng.choice(LAT_FIRST)}_{rng.choice(LAT_LAST)}"
            if re.search(r"\d", name):
                fake_value += str(rng.randrange(10, 999))
            fake_value = prefix + fake_value
            if fake_value not in self._used_aliases and not self._hits(fake_value, avoid):
                return fake_value
        return prefix + hashlib.sha256(name.encode()).hexdigest()[:12]

    def alias_for_name(self, name: str, avoid=None) -> str:
        if not self.fake:
            return self._register(name, f"USER_{len(self.name_map) + 1}")

        if _is_nick(name):
            return self._register(name, self._fake_username(name, avoid))

        words = name.split()
        if len(words) == 1 and self._guess_gender(words[0]) is None:
            return self._register(name, self._fake_org(name, avoid))
        gender = self._guess_gender(words[0])
        surnames = SURNAMES_N if gender is None else (SURNAMES_M if gender == "m" else SURNAMES_F)
        names = MALE_NAMES + FEMALE_NAMES if gender is None else \
            (MALE_NAMES if gender == "m" else FEMALE_NAMES)
        for attempt in range(50):
            rng = _det_rng("name", name, attempt)
            fake_value = f"{rng.choice(names)} {rng.choice(surnames)}"
            if fake_value not in self._used_aliases and not self._hits(fake_value, avoid):
                return self._register(name, fake_value)
        return self._register(name, self._fake_org(name, avoid))  # редчайший случай

    def reconcile(self) -> None:
        """Перегенерировать фейки, случайно совпавшие с реальными именами,
        чтобы самопроверка ловила только настоящие утечки."""
        real_names = set(self.name_map)
        for real in sorted(self.name_map):
            fake_value = self.name_map[real]
            if self._hits(fake_value, real_names):
                self._used_aliases.discard(fake_value)
                del self.name_map[real]
                self.alias_for_name(real, avoid=real_names)

    # --- компиляция замен (выполняется один раз после сбора имён) ---------------------

    def prepare(self) -> None:
        """Компилирует замены имён в regex-фазы с маркерами \x00N\x00:
        полные кириллические имена (по границам слов) -> латинские имена/ники
        как отдельное слово в прозе (пути/команды/переменные не трогаются).
        В отличие от скрипта-первоисточника, фаза «имён-обращений» (замена
        голого имени без границ слов) не используется: она портит слова
        вроде «Иванович» и ломает обратную подстановку."""
        self.reconcile()
        if not self.name_map:
            self._phases = []
            return

        # от длинных имён к коротким: важно для полных замен (подстрочные — кириллица)
        full_sorted = sorted(self.name_map.items(), key=lambda kv: -len(kv[0]))

        def _textual(r: str) -> bool:
            return len(r) >= 2 and bool(re.search(r"[А-Яа-яЁёA-Za-z]", r))

        cyr_items = [(r, a) for r, a in full_sorted
                     if _textual(r) and not re.search(r"[A-Za-z]", r)]
        lat_items = [(r, a) for r, a in full_sorted
                     if _textual(r) and re.search(r"[A-Za-z]", r)]

        # маркерные фазы: real -> \x00N\x00 -> подстановка
        values: list[str] = []

        def mark(val: str) -> str:
            values.append(val)
            return f"\x00{len(values) - 1}\x00"

        full_alts = "|".join(re.escape(r) for r, _ in cyr_items)
        full_re = re.compile(rf"\b(?:{full_alts})\b") if full_alts else None
        full_marks = {real: mark(alias) for real, alias in cyr_items}

        lat_re = None
        lat_marks = {}
        if lat_items:
            lat_alts = "|".join(re.escape(r) for r, _ in
                                sorted(lat_items, key=lambda kv: -len(kv[0])))
            lat_re = re.compile(rf"(?<!{CODE_BOUND})@?(?:{lat_alts})(?!{CODE_BOUND})")
            lat_marks = {r: mark(a) for r, a in lat_items}

        ph_re = re.compile(r"\x00(\d+)\x00")

        def decode(m: re.Match) -> str:
            return values[int(m.group(1))]

        self._phases = (full_re, full_marks, lat_re, lat_marks, ph_re, decode)

        # детектор утечек: не осталось ли реальных имён/ников после чистки
        leak_parts = [re.escape(r) for r, _ in cyr_items]
        self._leak_re = re.compile(rf"\b(?:{'|'.join(leak_parts)})\b") if leak_parts else None
        lat_leak_parts = [re.escape(r) for r, _ in lat_items]
        self._leak_lat_re = re.compile(
            rf"(?<!{CODE_BOUND})(?:{'|'.join(lat_leak_parts)})(?!{CODE_BOUND})"
        ) if lat_leak_parts else None

    # --- проверки ------------------------------------------------------------------------

    def leaks_in_text(self, s: str) -> int:
        """Сколько реальных значений осталось в тексте после чистки (0 — чисто).
        Проверяются не только имена/ники из карты, но и все регексные
        подстановки (телефоны/e-mail/ссылки/домены/IP): если какая-то фаза
        пропустила значение, запрос к LLM не уйдёт. Сначала из текста
        маскируются вставленные фейки — иначе фейк, содержащий реальный
        фрагмент (example.com внутри ab12cd34.example.com), даёт ложную
        тревогу."""
        if self._phases is None:
            self.prepare()
        count = 0
        if self._leak_re is not None and self._leak_re.search(s):
            count += 1
        if self._leak_lat_re is not None and self._leak_lat_re.search(s):
            count += 1
        if self._substitutions:
            masked = s
            for fake_value in sorted({f for _, f in self._substitutions}, key=len, reverse=True):
                masked = masked.replace(fake_value, "\x00")
            word_like = re.compile(r"^[\wА-Яа-яЁё@.\-]+$", re.UNICODE)
            for real, _fake in self._substitutions:
                if len(real) < 4:
                    continue  # короткие осколки дают ложные срабатывания
                if word_like.match(real):
                    hit = re.search(rf"(?<![\w]){re.escape(real)}(?![\w])", masked)
                else:
                    hit = real in masked
                if hit:
                    count += 1
        return count

    # --- очистка строк ---------------------------------------------------------------------

    def _fake_phone_repl(self, match: re.Match) -> str:
        cand = match.group(0)
        if not _phone_like(cand) or _defer_to_ru_pii(cand):
            return cand
        digits = "".join(ch for ch in cand if ch.isdigit())
        fake_digits = _fake_digits(digits)
        it = iter(fake_digits)
        fake_value = "".join(next(it) if ch.isdigit() else ch for ch in cand)
        self._record(cand, fake_value)
        self.stats["phones"] += 1
        return fake_value

    def _fake_email_repl(self, match: re.Match) -> str:
        addr = match.group(0)
        local, _, _domain = addr.partition("@")
        rng = _det_rng("email", addr)
        letters = "abcdefghjkmnpqrstuvwxyz"
        alpha = letters + "23456789"
        fake_local = rng.choice(letters) + "".join(rng.choice(alpha) for _ in local[1:])
        fake_value = f"{fake_local}@{rng.choice(FAKE_DOMAINS)}"
        self._record(addr, fake_value)
        return fake_value

    def _fake_link_repl(self, match: re.Match) -> str:
        url = match.group(0)
        code = hashlib.sha256(url.encode("utf-8")).hexdigest()[:10]
        fake_value = f"https://example.com/{code}"
        self._record(url, fake_value)
        return fake_value

    def _fake_mention_repl(self, match: re.Match) -> str:
        mention = match.group(0)
        rng = _det_rng("mention", mention)
        alpha = "abcdefghijklmnopqrstuvwxyz0123456789_"
        fake_value = "@" + "".join(rng.choice(alpha) for _ in mention[1:])
        self._record(mention, fake_value)
        return fake_value

    @staticmethod
    def _ip_is_public(ip: str) -> bool:
        o = [int(x) for x in ip.split(".")]
        if any(x > 255 for x in o):
            return False
        return not (o[0] in (0, 10, 127) or (o[0] == 172 and 16 <= o[1] <= 31)
                    or (o[0] == 192 and o[1] == 168) or (o[0] == 169 and o[1] == 254))

    def _fake_ip_repl(self, match: re.Match) -> str:
        """IPv4 -> другой детерминированный адрес того же класса: приватные
        остаются приватными, публичные уходят в документные RFC 5737."""
        ip = match.group(0)
        o = [int(x) for x in ip.split(".")]
        if any(x > 255 for x in o):
            return ip
        rng = _det_rng("ip", ip)
        if o[0] == 10:
            fake_value = f"10.{rng.randrange(0, 255)}.{rng.randrange(0, 255)}.{rng.randrange(1, 255)}"
        elif o[0] == 127:
            fake_value = f"127.{rng.randrange(0, 255)}.{rng.randrange(0, 255)}.{rng.randrange(1, 255)}"
        elif o[0] == 172 and 16 <= o[1] <= 31:
            fake_value = f"172.{rng.randrange(16, 32)}.{rng.randrange(0, 255)}.{rng.randrange(1, 255)}"
        elif o[0] == 192 and o[1] == 168:
            fake_value = f"192.168.{rng.randrange(0, 255)}.{rng.randrange(1, 255)}"
        elif o[0] == 169 and o[1] == 254:
            fake_value = f"169.254.{rng.randrange(0, 255)}.{rng.randrange(1, 255)}"
        else:
            base = rng.choice(["192.0.2.", "198.51.100.", "203.0.113."])
            fake_value = base + str(rng.randrange(1, 255))
        self._record(ip, fake_value)
        return fake_value

    def _fake_domain_repl(self, match: re.Match) -> str:
        """Голый домен -> фейковый: у хостов из 3+ меток сохраняем сервисный
        префикс (chat., mail., api.), детерминированно."""
        d = match.group(0)
        if not _is_domain_like(d):
            return d  # файл (nginx.conf) или не-домен — не трогаем
        self.stats["domains"] += 1
        code = hashlib.sha256(d.lower().encode()).hexdigest()[:8]
        labels = d.split(".")
        if len(labels) >= 3:
            fake_value = f"{labels[0]}.{code}.example.com"
        else:
            fake_value = f"{code}.example.com"
        self._record(d, fake_value)
        return fake_value

    def _fake_wildcard_domain_repl(self, match: re.Match) -> str:
        d = match.group(0)[2:]
        if not _is_domain_like(d):
            return match.group(0)
        self.stats["domains"] += 1
        code = hashlib.sha256(d.lower().encode()).hexdigest()[:8]
        labels = d.split(".")
        if len(labels) >= 3:
            fake_value = f"*.{labels[0]}.{code}.example.com"
        else:
            fake_value = f"*.{code}.example.com"
        self._record(match.group(0), fake_value)
        return fake_value

    def sanitize_string(self, s: str) -> str:
        """Замена имён по карте + телефоны/e-mail/ссылки/@упоминания/домены/IP."""
        self._secret_values = []  # маркеры секретов живут в рамках одного вызова
        if self._phases is None:
            self.prepare()
        if self._phases:
            (full_re, full_marks, lat_re, lat_marks, ph_re, decode) = self._phases
            if full_re is not None:
                s = full_re.sub(lambda m: full_marks[m.group(0)], s)
            if lat_re is not None:
                def lat_lookup(m: re.Match) -> str:
                    key = m.group(0)
                    if key.startswith("@"):
                        key = key[1:]
                        return "@" + lat_marks.get(key, key)
                    return lat_marks.get(key, m.group(0))
                s = lat_re.sub(lat_lookup, s)

        if self.fake:
            repl_phone, repl_email, repl_link, repl_mention = (
                self._fake_phone_repl, self._fake_email_repl,
                self._fake_link_repl, self._fake_mention_repl,
            )
            repl_wildcard, repl_domain, repl_ip = (
                self._fake_wildcard_domain_repl, self._fake_domain_repl, self._fake_ip_repl,
            )
        else:
            def repl_phone(m: re.Match) -> str:
                cand = m.group(0)
                if not _phone_like(cand) or _defer_to_ru_pii(cand):
                    return cand  # отдаём фазе ru_pii — см. _fake_phone_repl
                self._record(cand, "[PHONE]")
                self.stats["phones"] += 1
                return "[PHONE]"

            def _token(tok: str):
                def repl(m: re.Match) -> str:
                    self._record(m.group(0), tok)
                    return tok
                return repl

            repl_email, repl_link, repl_mention = (
                _token("[EMAIL]"), _token("[LINK]"), _token("[MENTION]")
            )

            def repl_wildcard(m: re.Match) -> str:
                if not _is_domain_like(m.group(0)[2:]):
                    return m.group(0)
                self._record(m.group(0), "*.[DOMAIN]")
                self.stats["domains"] += 1
                return "*.[DOMAIN]"

            def repl_domain(m: re.Match) -> str:
                d = m.group(0)
                if not _is_domain_like(d):
                    return d
                self._record(d, "[DOMAIN]")
                self.stats["domains"] += 1
                return "[DOMAIN]"

            def repl_ip(m: re.Match) -> str:
                self._record(m.group(0), "[IP]")
                return "[IP]"

        s, n = RE_LINK.subn(repl_link, s); self.stats["links"] += n
        # секреты — после ссылок: URL с ключом внутри фейкуется целиком как
        # ссылка, отдельные ключи ловит каталог секретов
        s = secrets.apply(s, self)
        s, n = RE_EMAIL.subn(repl_email, s); self.stats["emails"] += n
        s, n = RE_MENTION.subn(repl_mention, s); self.stats["mentions"] += n
        s = RE_WILDCARD_DOMAIN.sub(repl_wildcard, s)  # счётчик ведёт repl
        s = RE_DOMAIN.sub(repl_domain, s)  # счётчик ведёт repl
        s = RE_PHONE_CANDIDATE.sub(repl_phone, s)  # счётчик ведёт repl (пропуски не считаются)
        # RU-идентификаторы — ПОСЛЕ телефона: валидные СНИЛС/ИНН/ОГРН телефонная
        # фаза пропустила (см. _ru_identifier), а фейки ru_pii (11–16 цифр) уже
        # никому не матчятся — двойных подстановок нет
        s = ru_pii.apply(s, self)
        s, n = RE_IP.subn(repl_ip, s); self.stats["ips"] += n

        # раскрытие маркеров секретов (имена раскрываются своим ph_re ниже)
        if self._secret_values:
            s = re.sub(r"\x00s(\d+)\x00",
                       lambda m: self._secret_values[int(m.group(1))], s)

        if self._phases:
            s = ph_re.sub(decode, s)
        return s

    # --- обратная подстановка ----------------------------------------------------------

    def reverse_map(self) -> dict[str, str]:
        """Фейк -> реальное. Неоднозначные фейки (два разных реальных значения
        дали один и тот же фейк/плейсхолдер) в карту не попадают — их оператор
        правит руками. Повтор одного и того же реального значения (одно и то
        же число встречается в тексте несколько раз) неоднозначностью
        не считается: подстановки детерминированы, фейк всегда один."""
        reals_by_fake: dict[str, set[str]] = {}
        for real, fake_value in self._substitutions:
            reals_by_fake.setdefault(fake_value, set()).add(real)
        return {
            fake_value: next(iter(reals))
            for fake_value, reals in reals_by_fake.items()
            if len(reals) == 1
        }

    def de_anonymize(self, text: str) -> str:
        """Подставить реальные значения вместо фейковых в тексте ответа LLM.
        Замены идут от длинных фейков к коротким; словарные фейки — по границам
        слов, чтобы не портить совпадения внутри других слов."""
        rmap = self.reverse_map()
        if not rmap or not text:
            return text
        word_like = re.compile(r"^[\wА-Яа-яЁё@.\-]+$", re.UNICODE)
        for fake_value in sorted(rmap, key=len, reverse=True):
            real = rmap[fake_value]
            if word_like.match(fake_value):
                pattern = rf"(?<![\w]){re.escape(fake_value)}(?![\w])"
                text = re.sub(pattern, real.replace("\\", "\\\\"), text)
            else:
                text = text.replace(fake_value, real)
        return text
