# SDOM — проверка безопасности репозитория

Локальный сканер: секреты в git, лишняя инфраструктура в коде, рискованные настройки.

```bash
./security/sdom/sdom-configure.sh
./security/sdom/sdom-check.sh
```

Отчёт: `security/sdom/last-report.txt` (не коммитится).

## Что не должно попадать в git

- файлы с секретами (`.env`, ключи, токены)
- `static/admin/config.yml` с URL OAuth-прокси (только `config.yml.example` + генерация в CI)
- код Cloudflare Worker (`/workers/`)

Секреты — только в защищённых хранилищах платформы (CI Secrets, Worker Secrets).
