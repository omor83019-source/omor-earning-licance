OMOR EARNING — Python Telegram Bot + License API

লোকাল রান:
1) Python 3.10+
2) pip install -r requirements.txt
3) .env.example কপি করে .env করুন; নতুন Bot Token .env-এ বসান।
4) python bot.py
5) Admin Telegram account থেকে Bot-এ /start দিন।

Render:
1) এই ZIP-এর ফাইল GitHub Repository-তে আপলোড করুন।
2) Render-এ Web Service / Blueprint Deploy করুন।
3) TELEGRAM_BOT_TOKEN Environment Variable-এ নতুন Bot Token দিন।
4) Deploy হওয়ার পর Admin Bot-এ /connect https://আপনার-service.onrender.com পাঠান।
5) Bot একটি Connection Code দেবে। সেই কোড Extension-এ বসালেই API address + connector key সেট হবে।

নোট:
- Bot Token কখনো Extension-এ নেই।
- Connection Code Admin Bot তৈরি করে; নতুন /connect করলে আগের কোড বাতিল হবে।
- Connection Code shared client identifier; এটিকে গোপন Admin credential ভাববেন না।
- Admin-এর প্রথম /start Telegram update থেকে numeric ID bind করে; চাইলে ADMIN_TELEGRAM_ID দিয়ে আগেই lock করুন।
- Render-এ persistent disk যুক্ত করুন, নইলে instance restart/deploy-এ SQLite database হারাতে পারে।
