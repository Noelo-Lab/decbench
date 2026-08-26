"""Compilability fixup for decompiled C (the byte-match preprocessing pass).

Decompiler output rarely compiles as-is: Ghidra emits pseudo-types it never
defines (``undefined4``, ``code``, ``uint``), angr emits illegal C tokens like
``GLIBC_2.2.5::stderr`` (symbol-version names) and calls helpers that have no
declaration, Binary Ninja prints its own dialect (``arg3 @ rax``, ``u>>``,
untyped ``*(ptr + off)`` derefs). The recompilation byte-match metric scores
any non-compiling function as 0, so this pass exists to give every decompiler a
fair shot at recompiling: we *maximize compilation* by repairing the code the
same way for everyone, then let the (operand-normalized) assembly diff judge
correctness.

Strategy — deliberately conflict-safe:

1. **Token sanitization** removes or rewrites constructs no C compiler accepts
   (``NS::id`` version names, ``@ reg`` annotations, ``u>>`` operators,
   ``*(void *)`` derefs, Ghidra ``x._4_4_`` sub-piece reads, computed gotos,
   array return types) but that are unambiguous in decompiler output — none of
   these token shapes can occur in valid C, so the rewrites are safe for every
   backend.
2. **Minimal includes** (``stdint``/``stddef`` only) — NOT the full stdlib —
   so the scaffolding never collides with a decompiler's own ``typedef struct
   FILE {}`` etc. (forcing ``stdio.h`` was a real cause of redefinition errors).
3. **gcc-diagnostic-driven self-repair**: compile, read the diagnostics, and
   inject *only* what the compiler says is missing. Missing functions get the
   best prototype we can source — the decompiler's OWN signature for a sibling
   function of the same binary (``context_decls``), a curated libc prototype,
   an IDA/Ghidra helper macro (``LOBYTE``/``CONCAT44``/...), or a bare ``long
   f();`` — because prototype fidelity directly shapes call-site codegen
   (AL zeroing, argument widths, return sign-extensions). Missing types become
   width-matched typedefs; missing globals become width-typed definitions
   (IDA/Ghidra data-name prefixes encode the width); undefined ``struct X``
   gets a synthesized definition whose members are harvested from subsequent
   diagnostics. Because we add only what the compiler asks for, we never
   redefine something the decompiler already declared. Conflicts that we *do*
   cause (rare) are detected and the offending injected decl is withdrawn.
4. **Positional edits** for diagnostics that name no identifier (untyped void
   derefs, ``= {0}`` brace assignments, calls through data values): a minimal
   source rewrite at gcc's line:col, applied bottom-up.

The cost is some ABI/codegen noise (a synthesized member layout may not match
the real struct), but the metric's operand normalization absorbs the largest
source of pure-linking noise (call/branch targets, rip-relative slots), and the
alternative — scoring most of a decompiler's functions as a flat 0 because they
reference ``undefined4`` — is far less fair. Applied uniformly to all
decompilers, this isolates *logic* recompilation from *type recovery* (which
``type_match`` measures separately).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

# Forces ASCII quoting in gcc diagnostics so the repair regexes below match.
_C_LOCALE_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C", "LANGUAGE": "C"}
_Q = r"['‘’“”]"

_NS_QUALIFIER = re.compile(r"\b[A-Za-z_][\w.$]*::")
_BARE_SCOPE = re.compile(r"(?<![\w)\]>]):{2}(?=\s*[A-Za-z_])")

_ANNOTATION_KEYWORDS = re.compile(
    r"\b__(?:noreturn|pure|const|packed|noreturn__|hidden|usercall|userpurge"
    r"|cdecl|stdcall|fastcall|thiscall|vectorcall)\b"
)
_ANNOTATION_CALLS = re.compile(r'\b__convention\s*\([^)]*\)|\b__(?:reg|stack)\s*\("[^"]*"\)')

_AT_REG = re.compile(r"\s@\s*\w+")
_U_SHIFT = re.compile(r"(?<=\s)u(>>=|>>|<<=|<<)(?=\s)")
_VOID_DEREF = re.compile(r"\*\s*\(\s*void\s*\*\s*\)")
_SUBPIECE = re.compile(r"\b([A-Za-z_]\w*)\._(\d+)_([1248])_")
_SUBPIECE_TYPES = {
    "1": "unsigned char",
    "2": "unsigned short",
    "4": "unsigned int",
    "8": "unsigned long",
}
_GOTO_CAST = re.compile(r"\bgoto\s*\(\s*[^()]*\)\s*\(")
_ARRAY_RET = re.compile(r"^([A-Za-z_][\w \t]*?(?:\*+[ \t]*)?)\[\d+\][ \t]+(\w+[ \t]*\()", re.M)
_INT_F_SUFFIX = re.compile(r"(?<![\w.])(\d+)f\b")

_STRUCT_TYPEDEF = re.compile(r"typedef\s+struct\s+(\w+)\s*\{[^{}]*\}\s*\1\s*;")

_STRING_OR_CHAR = re.compile(r'"(?:[^"\\\n]|\\.)*"|\'(?:[^\'\\\n]|\\.)*\'')

_DIAGNOSTIC_LINE = re.compile(r"^(?:.*?:\s*)?((?:fatal )?error):\s*(.+)$", re.MULTILINE)
_DIAGNOSTIC_CLASS = re.compile(r"\[(-W[^\]\s]+)\]")
_DIAGNOSTIC_QUOTED = re.compile(r"'[^'\n]*'|‘[^’\n]*’|“[^”\n]*”|\"[^\"\n]*\"")
_DIAGNOSTIC_ABSOLUTE_PATH = re.compile(r"(?:[A-Za-z]:)?[/\\][^\s:]+")
_DIAGNOSTIC_SOURCE_EXCERPT = re.compile(r"^\s*\d+\s*\|")
_DIAGNOSTIC_LIMIT = 400


def _sub_outside_strings(pattern: re.Pattern, repl, code: str) -> str:
    """Apply ``pattern.sub(repl, ...)`` only to spans outside string literals."""
    out: list[str] = []
    pos = 0
    for m in _STRING_OR_CHAR.finditer(code):
        out.append(pattern.sub(repl, code[pos : m.start()]))
        out.append(m.group(0))
        pos = m.end()
    out.append(pattern.sub(repl, code[pos:]))
    return "".join(out)


_MINIMAL_INCLUDES = "#include <stdint.h>\n#include <stddef.h>\n"

_TYPE_GUESS: dict[str, str] = {
    "undefined": "unsigned char",
    "undefined1": "unsigned char",
    "undefined2": "unsigned short",
    "undefined3": "unsigned int",
    "undefined4": "unsigned int",
    "undefined5": "unsigned long",
    "undefined6": "unsigned long",
    "undefined7": "unsigned long",
    "undefined8": "unsigned long",
    "byte": "unsigned char",
    "uchar": "unsigned char",
    "sbyte": "signed char",
    "ushort": "unsigned short",
    "word": "unsigned short",
    "uint": "unsigned int",
    "dword": "unsigned int",
    "uint3": "unsigned int",
    "ulong": "unsigned long",
    "qword": "unsigned long",
    "uint5": "unsigned long",
    "uint6": "unsigned long",
    "uint7": "unsigned long",
    "ulonglong": "unsigned long long",
    "longlong": "long long",
    "pointer": "void *",
    # These MUST stay width-correct: a ``long`` fallback would silently widen
    # every 4-byte store/load to 8 bytes and wreck the recompiled codegen.
    "_byte": "unsigned char",
    "_word": "unsigned short",
    "_dword": "unsigned int",
    "_qword": "unsigned long long",
    "_oword": "long double",
    "_tbyte": "long double",
    "_bool1": "unsigned char",
    "_bool2": "unsigned short",
    "_bool4": "unsigned int",
    "_bool8": "unsigned long long",
    "_unknown": "unsigned char",
    "bool": "unsigned char",
    "__int8": "char",
    "__int16": "short",
    "__int32": "int",
    "__int64": "long long",
    "__uint8": "unsigned char",
    "__uint16": "unsigned short",
    "__uint32": "unsigned int",
    "__uint64": "unsigned long long",
    "float4": "float",
    "float8": "double",
    "float10": "long double",
    "unkbyte10": "long double",
    "unkuint10": "long double",
}

_SPECIAL_TYPEDEFS: dict[str, str] = {
    "code": "typedef long code();",
    "va_list": "typedef __builtin_va_list va_list;",
    "gcc_va_list": "typedef __builtin_va_list gcc_va_list;",
    "__gnuc_va_list": "typedef __builtin_va_list __gnuc_va_list;",
    "_Bool": "",
}
for _simd, _members in (
    (
        "__m128i",
        "signed char m128i_i8[16]; short m128i_i16[8]; int m128i_i32[4];"
        " long long m128i_i64[2]; unsigned char m128i_u8[16];"
        " unsigned short m128i_u16[8]; unsigned int m128i_u32[4];"
        " unsigned long long m128i_u64[2];",
    ),
    (
        "__m128",
        "float m128_f32[4]; unsigned long long m128_u64[2];"
        " signed char m128_i8[16]; int m128_i32[4];",
    ),
    ("__m128d", "double m128d_f64[2];"),
    ("__m64", "long long m64_i64; int m64_i32[2]; short m64_i16[4]; char m64_i8[8];"),
):
    _SPECIAL_TYPEDEFS[_simd] = f"typedef union {{ {_members} }} {_simd};"

_PSEUDO_TYPE_NAME = re.compile(
    r"^(?:undefined\d*|u?int\d+|u(?:char|short|int|long)|s?byte|[dq]word|word"
    r"|bool|code|float\d+|ulonglong|longlong|_(?:byte|word|dword|qword|oword"
    r"|tbyte|bool\d|unknown)|__u?int\d+|__m\d+[id]?|g?cc_va_list|va_list)$",
    re.IGNORECASE,
)

_DATA_NAME = re.compile(
    r"^(byte|word|dword|qword|off|unk|flt|dbl|xmmword|asc|stru|s|DAT|_DAT|PTR|dat)_[0-9a-fA-F_]+$"
)
_DATA_PREFIX_TYPE = {
    "byte": "unsigned char",
    "word": "unsigned short",
    "dword": "unsigned int",
    "qword": "unsigned long",
    "off": "void *",
    "unk": "unsigned char",
    "flt": "float",
    "dbl": "double",
    "xmmword": "long double",
    "asc": "char",
    "s": "char",
    "stru": "long",
    "DAT": "unsigned char",
    "_DAT": "unsigned char",
    "PTR": "void *",
    "dat": "long",
}
_DATA_ARRAY_PREFIXES = {"asc", "s", "unk", "stru"}


def _known_protos() -> dict[str, str]:
    """Curated real prototypes for common libc calls.

    Opaque struct pointers (``FILE *``, ``DIR *``) are spelled ``void *`` —
    codegen-identical for pointer args and it avoids dragging in typedefs the
    decompiler might also define. Prototype fidelity matters: a real prototype
    reproduces the original call-site codegen (no AL zeroing for non-variadic
    callees, correct argument widths, no bogus return sign-extensions).
    """
    protos: dict[str, str] = {}

    def add(decl: str) -> None:
        name = re.search(r"(\w+)\s*\(", decl).group(1)
        protos[name] = decl

    for d in (
        "int printf(const char *, ...);",
        "int fprintf(void *, const char *, ...);",
        "int sprintf(char *, const char *, ...);",
        "int snprintf(char *, unsigned long, const char *, ...);",
        "int vfprintf(void *, const char *, __builtin_va_list);",
        "int vsnprintf(char *, unsigned long, const char *, __builtin_va_list);",
        "int scanf(const char *, ...);",
        "int fscanf(void *, const char *, ...);",
        "int sscanf(const char *, const char *, ...);",
        "int puts(const char *);",
        "int fputs(const char *, void *);",
        "int fputc(int, void *);",
        "int putc(int, void *);",
        "int putchar(int);",
        "char *fgets(char *, int, void *);",
        "int fgetc(void *);",
        "int getc(void *);",
        "int getchar(void);",
        "int ungetc(int, void *);",
        "void *fopen(const char *, const char *);",
        "int fclose(void *);",
        "void *fdopen(int, const char *);",
        "void *freopen(const char *, const char *, void *);",
        "unsigned long fread(void *, unsigned long, unsigned long, void *);",
        "unsigned long fwrite(const void *, unsigned long, unsigned long, void *);",
        "int fflush(void *);",
        "int fseek(void *, long, int);",
        "long ftell(void *);",
        "void rewind(void *);",
        "int feof(void *);",
        "int ferror(void *);",
        "void clearerr(void *);",
        "int fileno(void *);",
        "void perror(const char *);",
        "int remove(const char *);",
        "int rename(const char *, const char *);",
        "void *popen(const char *, const char *);",
        "int pclose(void *);",
        "int setvbuf(void *, char *, int, unsigned long);",
        "void setbuf(void *, char *);",
        "void *tmpfile(void);",
        "unsigned long strlen(const char *);",
        "int strcmp(const char *, const char *);",
        "int strncmp(const char *, const char *, unsigned long);",
        "char *strcpy(char *, const char *);",
        "char *strncpy(char *, const char *, unsigned long);",
        "char *strcat(char *, const char *);",
        "char *strncat(char *, const char *, unsigned long);",
        "char *strchr(const char *, int);",
        "char *strrchr(const char *, int);",
        "char *strstr(const char *, const char *);",
        "char *strdup(const char *);",
        "char *strndup(const char *, unsigned long);",
        "char *strtok(char *, const char *);",
        "unsigned long strcspn(const char *, const char *);",
        "unsigned long strspn(const char *, const char *);",
        "char *strpbrk(const char *, const char *);",
        "int strcasecmp(const char *, const char *);",
        "int strncasecmp(const char *, const char *, unsigned long);",
        "int strcoll(const char *, const char *);",
        "char *strerror(int);",
        "void *memcpy(void *, const void *, unsigned long);",
        "void *memmove(void *, const void *, unsigned long);",
        "void *memset(void *, int, unsigned long);",
        "int memcmp(const void *, const void *, unsigned long);",
        "void *memchr(const void *, int, unsigned long);",
        "void *mempcpy(void *, const void *, unsigned long);",
        "void *malloc(unsigned long);",
        "void *calloc(unsigned long, unsigned long);",
        "void *realloc(void *, unsigned long);",
        "void free(void *);",
        "void exit(int);",
        "void _exit(int);",
        "void abort(void);",
        "int atexit(void *);",
        "int atoi(const char *);",
        "long atol(const char *);",
        "long long atoll(const char *);",
        "double atof(const char *);",
        "long strtol(const char *, char **, int);",
        "unsigned long strtoul(const char *, char **, int);",
        "long long strtoll(const char *, char **, int);",
        "unsigned long long strtoull(const char *, char **, int);",
        "double strtod(const char *, char **);",
        "char *getenv(const char *);",
        "int setenv(const char *, const char *, int);",
        "int unsetenv(const char *);",
        "int putenv(char *);",
        "int system(const char *);",
        "void qsort(void *, unsigned long, unsigned long, void *);",
        "void *bsearch(const void *, const void *, unsigned long, unsigned long, void *);",
        "int abs(int);",
        "long labs(long);",
        "int rand(void);",
        "void srand(unsigned int);",
        "long random(void);",
        "void srandom(unsigned int);",
        "int mkstemp(char *);",
        "char *realpath(const char *, char *);",
        "int open(const char *, int, ...);",
        "int close(int);",
        "long read(int, void *, unsigned long);",
        "long write(int, const void *, unsigned long);",
        "long lseek(int, long, int);",
        "int unlink(const char *);",
        "int access(const char *, int);",
        "int isatty(int);",
        "int getpid(void);",
        "int getppid(void);",
        "int fork(void);",
        "unsigned int getuid(void);",
        "unsigned int geteuid(void);",
        "unsigned int getgid(void);",
        "unsigned int getegid(void);",
        "int setuid(unsigned int);",
        "int setgid(unsigned int);",
        "int seteuid(unsigned int);",
        "int setegid(unsigned int);",
        "int dup(int);",
        "int dup2(int, int);",
        "int pipe(int *);",
        "unsigned int sleep(unsigned int);",
        "int usleep(unsigned int);",
        "int chdir(const char *);",
        "char *getcwd(char *, unsigned long);",
        "int rmdir(const char *);",
        "int mkdir(const char *, unsigned int);",
        "int chmod(const char *, unsigned int);",
        "int chown(const char *, unsigned int, unsigned int);",
        "int stat(const char *, void *);",
        "int lstat(const char *, void *);",
        "int fstat(int, void *);",
        "int kill(int, int);",
        "int raise(int);",
        "void *signal(int, void *);",
        "int execv(const char *, char *const *);",
        "int execvp(const char *, char *const *);",
        "long sysconf(int);",
        "int ioctl(int, unsigned long, ...);",
        "int fcntl(int, int, ...);",
        "unsigned int umask(unsigned int);",
        "int gethostname(char *, unsigned long);",
        "int uname(void *);",
        "int getpagesize(void);",
        "int ftruncate(int, long);",
        "int truncate(const char *, long);",
        "int link(const char *, const char *);",
        "int symlink(const char *, const char *);",
        "long readlink(const char *, char *, unsigned long);",
        "int *__errno_location(void);",
        "const unsigned short **__ctype_b_loc(void);",
        "const int **__ctype_tolower_loc(void);",
        "const int **__ctype_toupper_loc(void);",
        "int tolower(int);",
        "int toupper(int);",
        "int isalpha(int);",
        "int isdigit(int);",
        "int isalnum(int);",
        "int isspace(int);",
        "int isupper(int);",
        "int islower(int);",
        "int isprint(int);",
        "int ispunct(int);",
        "int isxdigit(int);",
        "int iscntrl(int);",
        "int isgraph(int);",
        "char *setlocale(int, const char *);",
        "long time(long *);",
        "long clock(void);",
        "int gettimeofday(void *, void *);",
        "void *localtime(const long *);",
        "void *gmtime(const long *);",
        "long mktime(void *);",
        "char *ctime(const long *);",
        "char *asctime(const void *);",
        "unsigned long strftime(char *, unsigned long, const char *, const void *);",
        "int nanosleep(const void *, void *);",
        "int clock_gettime(int, void *);",
        "int getopt(int, char *const *, const char *);",
        "int getopt_long(int, char *const *, const char *, const void *, int *);",
        "int getopt_long_only(int, char *const *, const char *, const void *, int *);",
        "void err(int, const char *, ...);",
        "void errx(int, const char *, ...);",
        "void warn(const char *, ...);",
        "void warnx(const char *, ...);",
        "void error(int, int, const char *, ...);",
        "void __assert_fail(const char *, const char *, unsigned int, const char *);",
        "int _setjmp(void *);",
        "int setjmp(void *);",
        "int __sigsetjmp(void *, int);",
        "void longjmp(void *, int);",
        "void siglongjmp(void *, int);",
        "void *opendir(const char *);",
        "void *readdir(void *);",
        "int closedir(void *);",
        "int __printf_chk(int, const char *, ...);",
        "int __fprintf_chk(void *, int, const char *, ...);",
        "int __sprintf_chk(char *, int, unsigned long, const char *, ...);",
        "int __snprintf_chk(char *, unsigned long, int, unsigned long, const char *, ...);",
        "void *__memcpy_chk(void *, const void *, unsigned long, unsigned long);",
        "void *__memset_chk(void *, int, unsigned long, unsigned long);",
        "char *__strcpy_chk(char *, const char *, unsigned long);",
        "char *__strcat_chk(char *, const char *, unsigned long);",
        "char *__strncpy_chk(char *, const char *, unsigned long, unsigned long);",
        "void __stack_chk_fail(void);",
        "long __fdelt_chk(long);",
        "int __vfprintf_chk(void *, int, const char *, __builtin_va_list);",
    ):
        add(d)
    return protos


_KNOWN_PROTOS = _known_protos()


def _helper_macros() -> dict[str, str]:
    """IDA defs.h-style partial-access macros + Ghidra pcode helper macros.

    Injected (only when the code calls them) as ``#define``s so both rvalue
    reads and lvalue writes (``LOWORD(v) = 0;``) work — restoring the real
    shift/mask semantics instead of compiling them as implicit-int CALLS.
    """
    m: dict[str, str] = {
        "LOBYTE": "#define LOBYTE(x) (*((unsigned char *)&(x)))",
        "LOWORD": "#define LOWORD(x) (*((unsigned short *)&(x)))",
        "LODWORD": "#define LODWORD(x) (*((unsigned int *)&(x)))",
        "HIBYTE": "#define HIBYTE(x) (*((unsigned char *)&(x) + sizeof(x) - 1))",
        "HIWORD": "#define HIWORD(x) (*(unsigned short *)((unsigned char *)&(x) + sizeof(x) - 2))",
        "HIDWORD": "#define HIDWORD(x) (*(unsigned int *)((unsigned char *)&(x) + sizeof(x) - 4))",
        "SLOBYTE": "#define SLOBYTE(x) (*((signed char *)&(x)))",
        "SLOWORD": "#define SLOWORD(x) (*((short *)&(x)))",
        "SLODWORD": "#define SLODWORD(x) (*((int *)&(x)))",
        "SHIBYTE": "#define SHIBYTE(x) (*((signed char *)&(x) + sizeof(x) - 1))",
        "SHIWORD": "#define SHIWORD(x) (*(short *)((unsigned char *)&(x) + sizeof(x) - 2))",
        "SHIDWORD": "#define SHIDWORD(x) (*(int *)((unsigned char *)&(x) + sizeof(x) - 4))",
        "COERCE_FLOAT": "#define COERCE_FLOAT(x) (*(float *)&(x))",
        "COERCE_DOUBLE": "#define COERCE_DOUBLE(x) (*(double *)&(x))",
        "COERCE_UNSIGNED_INT": "#define COERCE_UNSIGNED_INT(x) (*(unsigned int *)&(x))",
        "COERCE_UNSIGNED_INT64": "#define COERCE_UNSIGNED_INT64(x) (*(unsigned long long *)&(x))",
        "__CFADD__": "#define __CFADD__(x, y) ((unsigned long)(x) + (unsigned long)(y)"
        " < (unsigned long)(x))",
        "__CFSUB__": "#define __CFSUB__(x, y) ((unsigned long)(x) < (unsigned long)(y))",
        "__CFSHL__": "#define __CFSHL__(x, y) (((x) >> (8 * sizeof(x) - (y))) & 1)",
        "__OFADD__": "#define __OFADD__(x, y) __extension__({ __typeof__((x) + (y)) _x = (x),"
        " _y = (y), _s = _x + _y;"
        " (int)(((~(_x ^ _y)) & (_x ^ _s)) >> (8 * sizeof(_s) - 1)) & 1; })",
        "__OFSUB__": "#define __OFSUB__(x, y) __extension__({ __typeof__((x) - (y)) _x = (x),"
        " _y = (y), _s = _x - _y;"
        " (int)((((_x ^ _y)) & (_x ^ _s)) >> (8 * sizeof(_s) - 1)) & 1; })",
        "__PAIR16__": "#define __PAIR16__(h, l) (((unsigned short)(unsigned char)(h) << 8)"
        " | (unsigned char)(l))",
        "__PAIR32__": "#define __PAIR32__(h, l) (((unsigned int)(unsigned short)(h) << 16)"
        " | (unsigned short)(l))",
        "__PAIR64__": "#define __PAIR64__(h, l) (((unsigned long long)(unsigned int)(h) << 32)"
        " | (unsigned int)(l))",
        "__SPAIR64__": "#define __SPAIR64__(h, l) ((long long)(((unsigned long long)"
        "(unsigned int)(h) << 32) | (unsigned int)(l)))",
    }
    for n in range(1, 16):
        m[f"BYTE{n}"] = f"#define BYTE{n}(x) (*((unsigned char *)&(x) + {n}))"
        m[f"SBYTE{n}"] = f"#define SBYTE{n}(x) (*((signed char *)&(x) + {n}))"
    for n in range(1, 8):
        m[f"WORD{n}"] = f"#define WORD{n}(x) (*((unsigned short *)&(x) + {n}))"
        m[f"SWORD{n}"] = f"#define SWORD{n}(x) (*((short *)&(x) + {n}))"
    for n in range(1, 4):
        m[f"DWORD{n}"] = f"#define DWORD{n}(x) (*((unsigned int *)&(x) + {n}))"
        m[f"SDWORD{n}"] = f"#define SDWORD{n}(x) (*((int *)&(x) + {n}))"
    for n, t in (
        (1, "unsigned char"),
        (2, "unsigned short"),
        (4, "unsigned int"),
        (8, "unsigned long long"),
    ):
        bits = n * 8
        m[f"__ROL{n}__"] = (
            f"#define __ROL{n}__(x, y) ((({t})(x) << (y))" f" | (({t})(x) >> ({bits} - (y))))"
        )
        m[f"__ROR{n}__"] = (
            f"#define __ROR{n}__(x, y) ((({t})(x) >> (y))" f" | (({t})(x) << ({bits} - (y))))"
        )
    widths = {
        1: "unsigned char",
        2: "unsigned short",
        4: "unsigned int",
        8: "unsigned long long",
        16: "unsigned __int128",
    }
    swidths = {1: "signed char", 2: "short", 4: "int", 8: "long long", 16: "__int128"}
    for a in (1, 2, 3, 4, 5, 6, 7, 8):
        for b in (1, 2, 3, 4, 5, 6, 7, 8):
            total = a + b
            rt = widths.get(total) or ("unsigned long long" if total < 8 else "unsigned __int128")
            # An odd byte width (3/5/6/7) has no integer type to cast through,
            # so mask explicitly — pcode CONCAT truncates y.
            ymask = (
                f"(({rt})(y) & ((({rt})1 << {8 * b}) - 1))"
                if b < 8
                else f"({rt})(unsigned long long)(y)"
            )
            m[f"CONCAT{a}{b}"] = (
                f"#define CONCAT{a}{b}(x, y) ((({rt})(x) << {8 * b})" f" | {ymask})"
            )
    for a in (2, 4, 8, 16):
        for b in (1, 2, 4, 8):
            if b >= a:
                continue
            at = widths.get(a) or "unsigned __int128"
            bt = widths.get(b) or "unsigned long long"
            m[f"SUB{a}{b}"] = f"#define SUB{a}{b}(x, n) (({bt})(({at})(x) >> (8 * (n))))"
    for a in (1, 2, 4, 8):
        for b in (2, 4, 8, 16):
            if b <= a:
                continue
            m[f"ZEXT{a}{b}"] = f"#define ZEXT{a}{b}(x) (({widths[b]})({widths[a]})(x))"
            m[f"SEXT{a}{b}"] = f"#define SEXT{a}{b}(x) (({swidths[b]})({swidths[a]})(x))"
    return m


_HELPER_MACROS = _helper_macros()

_MAX_REPAIR_ITERS = 12


def _dedupe_struct_typedefs(code: str) -> str:
    """Drop duplicate ``typedef struct X {...} X;`` blocks (same tag defined
    twice can never compile); keep the definition with the most members."""
    found: dict[str, list[re.Match]] = {}
    for m in _STRUCT_TYPEDEF.finditer(code):
        found.setdefault(m.group(1), []).append(m)
    spans: list[tuple[int, int]] = []
    for _name, ms in found.items():
        if len(ms) < 2:
            continue
        keep = max(ms, key=lambda m: m.group(0).count(";"))
        spans.extend(m.span() for m in ms if m is not keep)
    for s, e in sorted(spans, reverse=True):
        code = code[:s] + code[e:]
    return code


def sanitize_tokens(code: str) -> str:
    """Remove or rewrite constructs no C compiler accepts but that are
    unambiguous in decompiler output (none of these token shapes can occur in
    valid C). String literals are left untouched.
    """
    code = _sub_outside_strings(_NS_QUALIFIER, "", code)
    code = _sub_outside_strings(_BARE_SCOPE, "", code)
    code = _sub_outside_strings(_ANNOTATION_KEYWORDS, "", code)
    code = _ANNOTATION_CALLS.sub("", code)
    code = _sub_outside_strings(_AT_REG, "", code)
    code = _sub_outside_strings(_U_SHIFT, r"\1", code)
    code = _sub_outside_strings(_VOID_DEREF, "*(unsigned long *)", code)
    code = _sub_outside_strings(
        _SUBPIECE,
        lambda m: f"(*({_SUBPIECE_TYPES[m.group(3)]} *)((char *)&{m.group(1)} + {m.group(2)}))",
        code,
    )
    code = _sub_outside_strings(_GOTO_CAST, "goto *(void *)(", code)
    code = _sub_outside_strings(_ARRAY_RET, lambda m: f"{m.group(1).strip()} *{m.group(2)}", code)
    code = _sub_outside_strings(_INT_F_SUFFIX, r"\1", code)
    code = _dedupe_struct_typedefs(code)
    return code


def _type_guess(name: str) -> str:
    """Best-effort concrete C type for an undefined pseudo-type name."""
    if name in _TYPE_GUESS:
        return _TYPE_GUESS[name]
    low = name.lower()
    if low in _TYPE_GUESS:
        return _TYPE_GUESS[low]
    m = re.fullmatch(r"u?int(\d+)", low)
    if m:
        n = int(m.group(1))
        width = "unsigned " if low.startswith("u") else ""
        bits = n if n in (16, 32, 64) else min(n, 8) * 8
        if bits <= 8:
            return f"{width}char"
        if bits <= 16:
            return f"{width}short"
        if bits <= 32:
            return f"{width}int"
        return f"{width}long"
    return "long"


def _typedef_decl(name: str, code: str) -> str:
    """The injected declaration for a missing TYPE name."""
    special = _SPECIAL_TYPEDEFS.get(name)
    if special is not None:
        return special
    if name == "bool":
        return "typedef _Bool bool;"
    if re.search(rf"\(\s*\*\s*\(\s*{re.escape(name)}\s*\*+\s*\)[^)]*\)\s*\(", code):
        return f"typedef long {name}();"
    return f"typedef {_type_guess(name)} {name};"


def _cast_context(code: str, name: str) -> bool:
    """Is ``name`` used as a TYPE in a cast? (gcc reports cast-only type names
    as plain undeclared identifiers, hiding their type-ness.)

    The value-cast alternative deliberately requires the next token to start a
    primary expression (identifier/paren/literal): ``(x) != 0``/``(x) - 1`` are
    ordinary parenthesized expressions, not casts. Data-symbol names
    (``dword_...``) are never cast types.
    """
    if _DATA_NAME.match(name):
        return False
    esc = re.escape(name)
    return bool(
        re.search(rf"\(\s*{esc}\s*\*+\s*\)", code)
        or re.search(rf"\(\s*{esc}\s*\)\s*[\w(\"']", code)
    )


def _global_decl(name: str, code: str) -> str:
    """The injected definition for a missing GLOBAL identifier.

    IDA/Ghidra data-name prefixes encode the width; names that are subscripted
    anywhere are declared as arrays so their access codegen (rip-relative lea)
    matches a real data symbol's.
    """
    m = _DATA_NAME.match(name)
    subscripted = re.search(rf"\b{re.escape(name)}\s*\[", code) is not None
    if m:
        ctype = _DATA_PREFIX_TYPE[m.group(1)]
        if subscripted or m.group(1) in _DATA_ARRAY_PREFIXES:
            return f"{ctype} {name}[1024];"
        return f"{ctype} {name};"
    if subscripted:
        return f"long {name}[1024];"
    return f"long {name};"


def derive_context_decls(function_codes: dict[str, str]) -> dict[str, str]:
    """Derive per-function prototypes from a decompilation's OWN output.

    ``function_codes`` maps function name -> decompiled code. The returned map
    (name -> ``"<signature>;"``) is passed to :func:`compile_with_fixup` as
    ``context_decls`` so calls to sibling functions of the same binary get the
    decompiler's own recovered signature instead of an unprototyped ``long
    f();`` — prototype presence and argument widths directly shape call-site
    codegen. Using the decompiler's own signatures keeps this fair: each
    backend benefits exactly from what it recovered.
    """
    protos: dict[str, str] = {}
    for name, code in function_codes.items():
        if not code:
            continue
        head_lines: list[str] = []
        done = False
        for line in code.split("\n"):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
                continue
            brace = stripped.find("{")
            head_lines.append(stripped[:brace] if brace != -1 else stripped)
            head = " ".join(head_lines)
            if brace != -1 or ("(" in head and head.count("(") == head.count(")")):
                done = brace != -1 or head.rstrip().endswith(")")
                break
            if len(head_lines) > 12:
                break
        if not done:
            continue
        sig = " ".join(head_lines).strip()
        if (
            not sig
            or len(sig) > 400
            or not sig.isascii()
            or ";" in sig
            or "#" in sig
            or "!" in sig
            or "*/" in sig
            or "=" in sig
            or "(" not in sig
            or not sig.endswith(")")
            or sig.count("(") != sig.count(")")
            or "decompilation failed" in sig.lower()
        ):
            continue
        nm = re.search(rf"\b{re.escape(name)}\s*\(", sig)
        if not nm:
            continue
        depth = 0
        close = -1
        for i in range(nm.end() - 1, len(sig)):
            if sig[i] == "(":
                depth += 1
            elif sig[i] == ")":
                depth -= 1
                if depth == 0:
                    close = i
                    break
        if close != len(sig) - 1:
            continue
        protos[name] = sanitize_tokens(sig) + ";"
    return protos


@dataclass
class FixupResult:
    """Outcome of a fixup compile attempt."""

    obj_path: Path | None
    source: str
    compilable: bool
    iterations: int
    injected: list[str] = field(default_factory=list)
    error: str | None = None


_RE_UNKNOWN_TYPE = re.compile(rf"unknown type name {_Q}([A-Za-z_]\w*){_Q}")
_RE_IMPLICIT_FUNC = re.compile(rf"implicit declaration of function {_Q}([A-Za-z_]\w*){_Q}")
_RE_UNDECLARED = re.compile(rf"{_Q}([A-Za-z_]\w*){_Q} undeclared")
_RE_NOT_A_FUNC = re.compile(rf"called object {_Q}([A-Za-z_]\w*){_Q}[^\n]*is not a function")
_RE_CONFLICT = re.compile(
    r"(?:conflicting types for|redefinition of|redeclared as|previous declaration of) "
    rf"{_Q}([A-Za-z_]\w*){_Q}"
)
_RE_BAD_ARGS = re.compile(rf"too (?:many|few) arguments to function {_Q}([A-Za-z_]\w*){_Q}")
_RE_DEREF_ERR = re.compile(
    r"(\d+):(\d+): error: (?:void value not ignored as it ought to be"
    r"|invalid use of void expression"
    r"|invalid type argument of unary '\*')"
)
_RE_BRACE_ASSIGN = re.compile(r"(\d+):(\d+): error: expected expression before '\{' token")
_RE_SCALAR_CALL = re.compile(r"(\d+):(\d+): error: called object[^\n]*is not a function")
_RE_RDONLY = re.compile(rf"error: assignment of read-only (?:variable|location) {_Q}?(\w+)?")
_RE_VOIDVAR = re.compile(rf"error: variable or field {_Q}(\w+){_Q} declared void")
_RE_UNDEF_STRUCT = re.compile(
    rf"error: (?:invalid use of undefined type {_Q}struct (\w+){_Q}"
    rf"|dereferencing pointer to incomplete type {_Q}struct (\w+){_Q}"
    rf"|array type has incomplete element type {_Q}struct (\w+){_Q}"
    rf"|storage size of {_Q}\w+{_Q} isn.t known)"
)
_RE_STORAGE_SIZE = re.compile(rf"error: storage size of {_Q}(\w+){_Q} isn.t known")
_RE_NO_MEMBER = re.compile(rf"{_Q}struct (\w+){_Q} has no member named {_Q}(\w+){_Q}")
_RE_NO_MEMBER_ANON = re.compile(
    rf"request for member {_Q}(\w+){_Q} in something not a structure or union"
)
_RE_PTR_ARROW = re.compile(rf"{_Q}\*(\w+){_Q} is a pointer; did you mean to use {_Q}->{_Q}")
_RE_ARRAY_ASSIGN = re.compile(r"error: assignment to expression with array type")
_RE_EXPECT_EXPR = re.compile(rf"error: expected expression before {_Q}(\w+){_Q}")
_RE_SUBSCRIPTED = re.compile(r"error: subscripted value is neither array nor pointer")
_RE_ERR_SNIPPET = re.compile(r"error: ([^\n]+)\n\s*\d+ \|([^\n]*)")


def _errors_with_snippets(stderr: str) -> list[tuple[str, str]]:
    return [(m.group(1), m.group(2)) for m in _RE_ERR_SNIPPET.finditer(stderr)]


def _summarize_compiler_errors(stderr: str) -> str:
    """Return a bounded, deterministic summary of compiler error lines."""
    classes: set[str] = set()
    messages: set[str] = set()
    for line in stderr.splitlines():
        if _DIAGNOSTIC_SOURCE_EXCERPT.match(line):
            continue
        match = _DIAGNOSTIC_LINE.match(line)
        if match is None:
            continue
        severity, message = match.groups()
        classes.update(_DIAGNOSTIC_CLASS.findall(message))
        message = _DIAGNOSTIC_CLASS.sub("", message)
        message = _DIAGNOSTIC_QUOTED.sub("<redacted>", message)
        message = _DIAGNOSTIC_ABSOLUTE_PATH.sub("<path>", message)
        if message.endswith(": No such file or directory"):
            message = re.sub(r"^\S+(?=: No such file or directory$)", "<path>", message)
        message = " ".join(message.split()).strip()
        if message:
            messages.add(f"{severity}: {message}")

    if not messages:
        return "unrepairable"

    class_prefix = f" [{', '.join(sorted(classes))}]" if classes else ""
    summary = f"compiler diagnostics{class_prefix}: {'; '.join(sorted(messages))}"
    if len(summary) <= _DIAGNOSTIC_LIMIT:
        return summary

    clipped = summary[: _DIAGNOSTIC_LIMIT - 3]
    boundary = max(clipped.rfind(" "), clipped.rfind(";"))
    if boundary >= _DIAGNOSTIC_LIMIT // 2:
        clipped = clipped[:boundary]
    return clipped.rstrip(" ,;") + "..."


def _has_language_mode(flags: list[str]) -> bool:
    """Whether direct caller flags select a C language mode."""
    for index, flag in enumerate(flags):
        if flag in {"-ansi", "--ansi"} or flag.startswith(("-std=", "--std=")):
            return True
        if (
            flag in {"-std", "--std"}
            and index + 1 < len(flags)
            and not flags[index + 1].startswith("-")
        ):
            return True
    return False


def _build_source(code: str, decls: dict[str, str], structs: dict[str, list[str]]) -> str:
    """Assemble the candidate TU: includes + synthesized structs + injected
    decls/macros + code."""
    sdefs = "\n".join(
        f"struct {name} {{ {' '.join(structs[name]) or 'long __db_pad;'} }};"
        for name in sorted(structs)
    )
    inject = "\n".join(decls[k] for k in sorted(decls) if decls[k])
    head = _MINIMAL_INCLUDES + sdefs + ("\n" if sdefs else "") + inject
    return head + ("\n\n" if (inject or sdefs) else "\n") + code


def _header_lines(decls: dict[str, str], structs: dict[str, list[str]]) -> int:
    """Number of lines the scaffolding occupies before ``code`` in the TU."""
    return _build_source("", decls, structs).count("\n")


def _gcc_compile(
    src: str, obj_path: Path, compiler: str, flags: list[str]
) -> subprocess.CompletedProcess:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(src)
        src_path = Path(f.name)
    try:
        return subprocess.run(
            [compiler, *flags, "-o", str(obj_path), str(src_path)],
            capture_output=True,
            timeout=30,
            text=True,
            env=_C_LOCALE_ENV,
        )
    finally:
        src_path.unlink(missing_ok=True)


def _proto_for(name: str, context_decls: dict[str, str] | None) -> str:
    """Best available prototype for a missing function, in fidelity order:
    the decompiler's own sibling signature, a curated libc prototype, a helper
    macro, then a bare unprototyped decl."""
    if context_decls and name in context_decls:
        return context_decls[name]
    if name in _KNOWN_PROTOS:
        return _KNOWN_PROTOS[name]
    if name in _HELPER_MACROS:
        return _HELPER_MACROS[name]
    return f"long {name}();"


def _apply_edits(code: str, hdr_lines: int, edits: list[tuple[int, int, object]]) -> str:
    """Apply positional repairs (bottom-up) at gcc line:col positions.

    ``edits`` entries are 1-based TU coordinates; ``hdr_lines`` maps them into
    ``code``. Kinds: ``deref`` (insert a word-width cast after the ``*`` at the
    caret), ``brace`` (replace ``{...}`` with ``0``), ``call`` (wrap the callee
    in a function-pointer cast).
    """
    lines = code.split("\n")
    for ln1, col1, kind in sorted(set(edits), reverse=True):
        ln, col = ln1 - 1 - hdr_lines, col1 - 1
        if not (0 <= ln < len(lines)):
            continue
        line = lines[ln]
        if kind == "deref":
            c = col
            while c < len(line):
                ch = line[c]
                if ch in "!~- \t(" or (ch == "=" and line[c + 1 : c + 2] != "="):
                    c += 1
                else:
                    break
            if c < len(line) and line[c] == "*" and not line.startswith("(unsigned long *)", c + 1):
                lines[ln] = line[: c + 1] + "(unsigned long *)" + line[c + 1 :]
            elif line[col : col + 1] == "=" or (c < len(line) and line[c] != "*"):
                b = col - 1
                while b >= 0 and line[b] in " \t":
                    b -= 1
                while b >= 0 and (line[b].isalnum() or line[b] in "_])"):
                    b -= 1
                if b >= 0 and line[b] == "*" and not line.startswith("(unsigned long *)", b + 1):
                    lines[ln] = line[: b + 1] + "(unsigned long *)" + line[b + 1 :]
        elif kind == "brace" and col < len(line) and line[col] == "{":
            close = line.find("}", col)
            if close != -1:
                lines[ln] = line[:col] + "0" + line[close + 1 :]
        elif kind == "call":
            m = re.match(
                r"(\(\*\w+(?:\[[^\]]*\])?\)|\*?[A-Za-z_]\w*(?:->\w+|\.\w+|\[[^\]]*\])*)\s*\(",
                line[col:],
            )
            if m and not line.startswith("((long (*)())", max(0, col - 13)):
                callee = m.group(1)
                lines[ln] = (
                    line[:col] + "((long (*)())(" + callee + "))" + line[col + len(callee) :]
                )
    return "\n".join(lines)


def compile_with_fixup(
    code: str,
    func_name: str,
    compiler: str = "gcc",
    flags: list[str] | None = None,
    context_decls: dict[str, str] | None = None,
) -> FixupResult:
    """Compile decompiled ``code`` to an object file, maximizing the odds it builds.

    Runs token sanitization, then a gcc-diagnostic-driven self-repair loop that
    injects only the declarations the compiler reports missing and applies
    minimal positional edits for diagnostics that name no identifier. Returns a
    :class:`FixupResult`; ``obj_path`` is set (and exists) iff compilation
    eventually succeeded. The caller owns ``obj_path`` and must unlink it.

    ``context_decls`` optionally maps sibling function names (from the same
    decompilation) to *the decompiler's own* recovered signatures; they are
    injected only when gcc reports the function missing, giving internal calls
    real prototypes (which reproduces the original call-site codegen).
    """
    if flags is None:
        flags = ["-O2", "-c", "-fno-builtin"]
    # No -w: implicit-declaration warnings are what drive prototype injection.
    flags = [f for f in flags if f != "-w"]
    if not _has_language_mode(flags):
        flags.append("-std=gnu17")
    flags.extend(
        [
            "-Wno-error=incompatible-pointer-types",
            "-Wno-error=int-conversion",
        ]
    )

    code = sanitize_tokens(code)
    decls: dict[str, str] = {}
    structs: dict[str, list[str]] = {}
    obj_dir = Path(tempfile.mkdtemp(prefix="decbench_bm_"))
    obj_path = obj_dir / f"{func_name}.o"

    def injected() -> list[str]:
        return [d for d in decls.values() if d] + [f"struct {n} {{...}}" for n in structs]

    def fail(src: str, iteration: int, error: str) -> FixupResult:
        shutil.rmtree(obj_dir, ignore_errors=True)
        return FixupResult(None, src, False, iteration, injected(), error)

    last_err = ""
    for iteration in range(1, _MAX_REPAIR_ITERS + 1):
        src = _build_source(code, decls, structs)
        try:
            proc = _gcc_compile(src, obj_path, compiler, flags)
        except subprocess.TimeoutExpired:
            return fail(src, iteration, "timeout")
        except FileNotFoundError:
            return fail(src, iteration, "compiler-not-found")

        if proc.returncode == 0 and obj_path.exists():
            new = {}
            for name in set(_RE_IMPLICIT_FUNC.findall(proc.stderr)):
                if name != func_name and name not in decls:
                    new[name] = _proto_for(name, context_decls)
            if new and iteration < _MAX_REPAIR_ITERS:
                decls.update(new)
                src2 = _build_source(code, decls, structs)
                try:
                    proc2 = _gcc_compile(src2, obj_path, compiler, flags)
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    proc2 = None
                if proc2 is not None and proc2.returncode == 0 and obj_path.exists():
                    return FixupResult(obj_path, src2, True, iteration + 1, injected())
                err2 = proc2.stderr if proc2 is not None else ""
                for name in set(_RE_CONFLICT.findall(err2)) | set(_RE_BAD_ARGS.findall(err2)):
                    if name in new:
                        decls[name] = f"long {name}();" if _RE_BAD_ARGS.search(err2) else ""
                src3 = _build_source(code, decls, structs)
                try:
                    proc3 = _gcc_compile(src3, obj_path, compiler, flags)
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    proc3 = None
                if proc3 is not None and proc3.returncode == 0 and obj_path.exists():
                    return FixupResult(obj_path, src3, True, iteration + 2, injected())
                for name in new:
                    decls.pop(name, None)
                src = _build_source(code, decls, structs)
                try:
                    _gcc_compile(src, obj_path, compiler, flags)
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    return fail(src, iteration, "timeout")
            return FixupResult(obj_path, src, True, iteration, injected())

        last_err = proc.stderr
        hdr_lines = _header_lines(decls, structs)
        pairs = _errors_with_snippets(last_err)
        added = False

        header_line_list = _build_source("", decls, structs).split("\n")
        withdrew = False
        for m in re.finditer(r"(?:^|\n)[^\n:]*:(\d+):\d+: error: ([^\n]+)", last_err):
            ln0 = int(m.group(1)) - 1
            msg = m.group(2)
            if not (0 <= ln0 < hdr_lines and ln0 < len(header_line_list)):
                continue
            if not (
                msg.startswith("expected")
                or "before" in msg
                or "stray" in msg
                or "declaration" in msg
            ):
                continue
            bad_line = header_line_list[ln0].strip()
            for nm, d in list(decls.items()):
                if d and d.strip() == bad_line:
                    decls[nm] = ""
                    withdrew = True
                    added = True
                    break
        if withdrew:
            continue

        for name in _RE_CONFLICT.findall(last_err):
            if decls.get(name):
                decls[name] = ""
                added = True
        for name in _RE_BAD_ARGS.findall(last_err):
            if decls.get(name) and decls[name] != f"long {name}();":
                decls[name] = f"long {name}();"
                added = True

        for name in _RE_UNKNOWN_TYPE.findall(last_err):
            if name not in decls:
                decls[name] = _typedef_decl(name, code)
                added = True

        for name in set(_RE_IMPLICIT_FUNC.findall(last_err)):
            if name == func_name:
                continue
            if _PSEUDO_TYPE_NAME.match(name):
                decl = _typedef_decl(name, code)
            else:
                decl = _proto_for(name, context_decls)
            if decls.get(name) != decl:
                decls[name] = decl
                added = True

        for name in _RE_UNDECLARED.findall(last_err):
            if name not in decls:
                if name in _HELPER_MACROS:
                    decls[name] = _HELPER_MACROS[name]
                elif _PSEUDO_TYPE_NAME.match(name) or _cast_context(code, name):
                    decls[name] = _typedef_decl(name, code)
                else:
                    decls[name] = _global_decl(name, code)
                added = True

        for msg, snip in pairs:
            if not msg.startswith("expected"):
                continue
            for m in re.finditer(r"\(\s*([A-Za-z_]\w*)\s*\**\s*\)", snip):
                name = m.group(1)
                if decls.get(name) == f"long {name};" and _cast_context(code, name):
                    decls[name] = _typedef_decl(name, code)
                    added = True

        deref_edits: list[tuple[int, int, object]] = []
        for m in _RE_DEREF_ERR.finditer(last_err):
            block_end = last_err.find("error:", m.end())
            block = last_err[m.end() : block_end if block_end != -1 else len(last_err)]
            sm = re.search(r"\d+ \|([^\n]*)", block)
            snip = sm.group(1) if sm else ""
            handled = False
            for cm in re.finditer(r"\*\s*\(?\s*([A-Za-z_]\w*)\s*\(", snip):
                name = cm.group(1)
                if name == func_name:
                    continue
                cur = decls.get(name)
                if cur in (None, f"long {name}();"):
                    decls[name] = f"long *{name}();"
                    handled = True
                    added = True
                elif "(" in (cur or ""):
                    handled = True
            if not handled:
                for cm in re.finditer(r"\*\s*([A-Za-z_]\w*)\s*[^\w(]", snip):
                    name = cm.group(1)
                    d = decls.get(name, "")
                    if d == f"long {name};":
                        decls[name] = f"long *{name};"
                        handled = True
                        added = True
                    elif d.startswith("long ") and re.search(
                        rf"\(\s*\*\s*{re.escape(name)}\s*\)\s*\(", code
                    ):
                        decls[name] = f"long (*{name})();"
                        handled = True
                        added = True
                    elif "*" in d:
                        handled = True
            if not handled:
                deref_edits.append((int(m.group(1)), int(m.group(2)), "deref"))

        if "invalid use of void expression" in last_err or "void value not ignored" in last_err:
            for msg, snip in pairs:
                if "void" not in msg:
                    continue
                for name in set(re.findall(r"([A-Za-z_]\w*)\s*[\[+]", snip)):
                    pat = re.compile(rf"\bvoid\s*\*\s*(?={re.escape(name)}\b)")
                    new_code, n = pat.subn("unsigned char *", code)
                    if n:
                        code = new_code
                        added = True

        for m in _RE_BRACE_ASSIGN.finditer(last_err):
            deref_edits.append((int(m.group(1)), int(m.group(2)), "brace"))
        for name in set(_RE_NOT_A_FUNC.findall(last_err)):
            if decls.get(name):
                decls[name] = ""
                added = True
            pat = re.compile(rf"(?<![\w.>)]){re.escape(name)}\s*\(")
            new_code, n = pat.subn(f"((long (*)()){name})(", code)
            if n:
                code = new_code
                added = True
        for m in _RE_SCALAR_CALL.finditer(last_err):
            if re.search(rf"called object {_Q}", m.group(0)):
                continue
            block_end = last_err.find("error:", m.end())
            block = last_err[m.end() : block_end if block_end != -1 else len(last_err)]
            sm = re.search(r"\d+ \|([^\n]*)", block)
            snip = sm.group(1) if sm else ""
            handled = False
            for cm in re.finditer(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)\s*\(", snip):
                name = cm.group(1)
                d = decls.get(name)
                if d is None or (d and "(" not in d):
                    decls[name] = f"long (*{name})();"
                    handled = True
                    added = True
            if not handled:
                pat = re.compile(
                    r"\(\s*\*\s*\(\s*unsigned long\s*\*\s*\)\s*([A-Za-z_]\w*)\s*\)\s*\("
                )
                if pat.search(snip):
                    new_code, n = pat.subn(r"(*(long (**)())&\1)(", code)
                    if n:
                        code = new_code
                        handled = True
                        added = True
            if not handled:
                deref_edits.append((int(m.group(1)), int(m.group(2)), "call"))
        if deref_edits:
            new_code = _apply_edits(code, hdr_lines, deref_edits)
            if new_code != code:
                code = new_code
                added = True

        struct_names = set()
        for m in _RE_UNDEF_STRUCT.finditer(last_err):
            name = next((g for g in m.groups() if g), None)
            if name:
                struct_names.add(name)
        for m in _RE_STORAGE_SIZE.finditer(last_err):
            var = m.group(1)
            dm = re.search(rf"\bstruct\s+(\w+)\s+{re.escape(var)}\b", code)
            if dm:
                struct_names.add(dm.group(1))
        for name in struct_names:
            if re.search(rf"\bstruct\s+{re.escape(name)}\s*\{{", code):
                continue
            if name not in structs:
                structs[name] = []
                added = True
        for m in _RE_NO_MEMBER.finditer(last_err):
            tag, member = m.group(1), m.group(2)
            if tag in structs and f"long {member};" not in structs[tag]:
                structs[tag].append(f"long {member};")
                added = True

        for m in _RE_NO_MEMBER_ANON.finditer(last_err):
            member = m.group(1)
            simd = {"m128i": "__m128i", "m128": "__m128", "m128d": "__m128d", "m64": "__m64"}.get(
                member.split("_")[0]
            )
            for msg, snip in pairs:
                if f"request for member '{member}'" not in msg:
                    continue
                if simd:
                    call = re.search(
                        rf"([A-Za-z_]\w*)\s*\((?:[^()]|\([^()]*\))*\)\s*\.\s*{re.escape(member)}",
                        snip,
                    )
                    if call and call.group(1) != func_name:
                        decls[call.group(1)] = f"{simd} {call.group(1)}();"
                        decls.setdefault(simd, _SPECIAL_TYPEDEFS[simd])
                        added = True
                        continue
                bm = re.search(
                    rf"([A-Za-z_]\w*)(?:\[[^\]]*\])?\s*(?:->|\.)\s*{re.escape(member)}", snip
                )
                if not bm:
                    continue
                var = bm.group(1)
                d = decls.get(var, "")
                if d == f"long {var};":
                    decls[var] = f"struct {{ long {member}; }} {var};"
                    added = True
                    continue
                if (
                    d.startswith("struct { ")
                    and d.endswith(f"}} {var};")
                    and f"long {member};" not in d
                ):
                    decls[var] = d.replace("struct { ", f"struct {{ long {member}; ", 1)
                    added = True
                    continue
                tm = re.search(rf"\b([A-Za-z_]\w*)\s*\**\s*{re.escape(var)}\s*[;,)\[=]", code)
                if not tm:
                    continue
                tname = tm.group(1)
                if tname in _SPECIAL_TYPEDEFS:
                    continue
                cur = decls.get(tname, "")
                if cur.startswith("typedef") and "struct" not in cur and "(" not in cur:
                    decls[tname] = f"typedef struct {{ long {member}; }} {tname};"
                    added = True
                elif cur.startswith("typedef struct {") and f"long {member};" not in cur:
                    decls[tname] = cur.replace(
                        "typedef struct { ", f"typedef struct {{ long {member}; ", 1
                    )
                    added = True

        if _RE_SUBSCRIPTED.search(last_err):
            for msg, snip in pairs:
                if "subscripted value" not in msg:
                    continue
                for m in re.finditer(r"([A-Za-z_]\w*)\s*\[", snip):
                    name = m.group(1)
                    d = decls.get(name, "")
                    if d.endswith(f" {name};") and "[" not in d and "(" not in d:
                        base = d[: -len(f" {name};")]
                        decls[name] = f"{base} {name}[1024];"
                        added = True

        if _RE_ARRAY_ASSIGN.search(last_err):
            for msg, snip in pairs:
                if "array type" not in msg:
                    continue
                m = re.search(r"([A-Za-z_]\w*)\s*=[^=]", snip)
                if not m:
                    continue
                name = m.group(1)
                d = decls.get(name, "")
                if d.endswith(f" {name}[1024];"):
                    decls[name] = d.replace(f" {name}[1024];", f" *{name};")
                    added = True
                    continue
                pat = re.compile(rf"(\b[\w ]+?[\w*])\s+{re.escape(name)}\s*\[\d+\]\s*;")
                new_code, n = pat.subn(rf"\1 *{name};", code, count=1)
                if n:
                    code = new_code
                    added = True

        for name in set(_RE_PTR_ARROW.findall(last_err)):
            esc = re.escape(name)
            pat = re.compile(rf"\*\(\s*{esc}\s*\)\s*->|\*{esc}\s*->")
            new_code, n = pat.subn(f"(*({name}))->", code)
            if n:
                code = new_code
                added = True

        for msg, snip in pairs:
            m = _RE_EXPECT_EXPR.search("error: " + msg)
            if not m:
                continue
            name = m.group(1)
            if name == func_name or not re.search(rf"\b{re.escape(name)}\s*\(", snip):
                continue
            is_typedef = bool(
                (decls.get(name, "").startswith("typedef"))
                or re.search(rf"typedef[^;{{]*\b{re.escape(name)}\s*;", code)
                or re.search(rf"}}\s*{re.escape(name)}\s*;", code)
            )
            if not is_typedef:
                continue
            pat = re.compile(rf"(?<![\w.>]){re.escape(name)}\s*\((?!\s*\*)")
            new_code, n = pat.subn(f"__dbfix_{name}(", code)
            if n and f"__dbfix_{name}" not in decls:
                proto = _KNOWN_PROTOS.get(name)
                decls[f"__dbfix_{name}"] = (
                    proto.replace(f"{name}(", f"__dbfix_{name}(", 1)
                    if proto
                    else f"long __dbfix_{name}();"
                )
                code = new_code
                added = True

        for m in re.finditer(
            rf"has no member named {_Q}(\w+){_Q}; did you mean {_Q}(\w+){_Q}", last_err
        ):
            wrong, right = m.group(1), m.group(2)
            pat = re.compile(rf"((?:->|\.)\s*){re.escape(wrong)}\b")
            new_code, n = pat.subn(rf"\g<1>{right}", code)
            if n:
                code = new_code
                added = True

        for msg, snip in pairs:
            bm = re.search(
                rf"invalid operands to binary (\S+) \(have {_Q}([^'‘’]+?){_Q}"
                rf"(?: {{aka[^}}]*}})? and {_Q}([^'‘’]+?){_Q}",
                msg,
            )
            if not bm:
                continue
            op, ta, tb = bm.group(1), bm.group(2), bm.group(3)
            if op not in ("-", "+", "*", "|", "&", "^", ">>", "<<", "%", "/"):
                continue
            la, lb = ta.rstrip().endswith("*"), tb.rstrip().endswith("*")
            if (
                not (la or lb)
                or ta.startswith(("struct", "union"))
                or tb.startswith(("struct", "union"))
            ):
                continue
            esc_op = re.escape(op)
            if lb:
                m2 = re.search(rf"{esc_op}\s*([A-Za-z_]\w*)\b(?!\s*[\[(])", snip)
                if m2:
                    name = m2.group(1)
                    cast = f"({ta.strip()})" if (la and op == "-") else "(long)"
                    pat = re.compile(rf"({esc_op}\s*){re.escape(name)}\b(?!\s*[\[(])")
                    new_code, n = pat.subn(rf"\g<1>{cast}{name}", code, count=8)
                    if n:
                        code = new_code
                        added = True
                        continue
            if la and not lb:
                m2 = re.search(rf"([A-Za-z_]\w*)\s*{esc_op}", snip)
                if m2:
                    name = m2.group(1)
                    pat = re.compile(rf"\b{re.escape(name)}(\s*{esc_op})")
                    new_code, n = pat.subn(rf"(long){name}\g<1>", code, count=8)
                    if n:
                        code = new_code
                        added = True

        if "cast specifies function type" in last_err:
            for name, d in list(decls.items()):
                if d == f"typedef long {name}();":
                    pat = re.compile(rf"\(\s*{re.escape(name)}\s*\)(?!\s*\*)")
                    new_code, n = pat.subn("(long)", code)
                    if n:
                        code = new_code
                        added = True

        for name in _RE_RDONLY.findall(last_err):
            if not name:
                continue
            pat = re.compile(rf"^(\s*)([^;{{}}\n]*?\bconst\b[^;\n]*\b{re.escape(name)}\b)", re.M)
            new_code = pat.sub(
                lambda m: m.group(1) + re.sub(r"\bconst\b\s*", "", m.group(2)), code, count=1
            )
            if new_code != code:
                code = new_code
                added = True

        for name in _RE_VOIDVAR.findall(last_err):
            new_code = re.sub(rf"\bvoid(\s+{re.escape(name)}\s*[;\[=])", r"long\1", code, count=1)
            if new_code != code:
                code = new_code
                added = True

        if not added:
            break

    return fail(
        _build_source(code, decls, structs),
        iteration,
        _summarize_compiler_errors(last_err),
    )
