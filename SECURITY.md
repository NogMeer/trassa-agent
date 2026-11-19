# Безопасность / Security

## Русский

Агент работает на серверах клиентов, часть его кода выполняется с правами root. Поэтому мы относимся к сообщениям об уязвимостях с наивысшим приоритетом.

**Как сообщить.** Не открывайте публичный issue. Отправьте [приватный отчёт GitHub](https://github.com/NogMeer/trassa-agent/security/advisories/new). Укажите:
- что именно уязвимо;
- как воспроизвести;
- какую версию или какой коммит вы проверяли.

**Что будет дальше.** Мы подтвердим получение и согласуем с вами срок исправления. Публикуем подробности после выпуска исправления и указываем автора, если он не против.

**Что особенно важно:**
- выполнение операции без действительной подписи панели;
- повтор или подмена операции;
- выход за пределы каталога операций;
- повышение прав процесса `trassa-agent` через `trassa-helper`;
- утечка секретов в журналы и метрики;
- обход автоотката.

## English

The agent runs on customer servers, and part of it runs as root. We treat vulnerability reports as the highest priority.

**How to report.** Do not open a public issue. Submit a [private GitHub report](https://github.com/NogMeer/trassa-agent/security/advisories/new). Include:
- what exactly is vulnerable;
- how to reproduce it;
- the version or commit you tested.

**What happens next.** We confirm receipt and agree on a fix timeline with you. Details are published after the fix ships, with credit to the reporter if they wish.

**Areas of particular interest:**
- running an operation without a valid panel signature;
- operation replay or tampering;
- escaping the operation catalog;
- privilege escalation from `trassa-agent` through `trassa-helper`;
- secrets leaking into logs or metrics;
- bypassing auto-rollback.
