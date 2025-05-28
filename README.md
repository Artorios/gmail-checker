Простой пример сканирования вложений в gmail почте яра правилами.
Сканируются только CHECK_LAST_N последних писем  
    
Установка:  
+ pip install -r requirements.txt
+ cp .env.example .env  
+ Прописать в .env файле gmail почту и пароль.  
_Gmail не поддерживает вход с "менее безопасных приложений" по обычному паролю. 
Пароль нужно сгенерировать App Password в Google Account → Security → App passwords_


