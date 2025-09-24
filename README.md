# 🌍 Gamified Disaster Preparedness & Response Education System  

> 🎮 A fun, interactive, and educational platform that teaches **disaster preparedness and response** through gamified learning modules.  
> Built with **Flask (Python)** backend, **MongoDB** database, and a simple **HTML/CSS/JS frontend**.  

---

## ✨ Features  

- ✅ **User Registration & Login** (Email/Password + Google Sign-In)  
- 🔑 **JWT Authentication** (secure, stateless sessions)  
- 🎯 **Gamified Learning Modules** (track progress, assignments, and scores)  
- 📤 **Upload Assignments** (submit photos as base64 images)  
- 🧑‍🎓 **Student Profiles** (personal + school info)  
- 🛠️ **Admin Dashboard** (list all users & progress with secret key)  
- 🌐 **CORS Protected** (secured to your frontend origin)  
- ❤️ **Healthcheck Endpoint** (quick DB + server check)  

---
---

## ⚙️ Installation & Setup  

### 1️⃣ Clone the repository  
```bash
git clone https://github.com/yourusername/Gamified-Disaster-Preparedness-and-Response-Education-System.git
cd Gamified-Disaster-Preparedness-and-Response-Education-System/lifesafe-flask

python -m venv venv
source venv/bin/activate    # Mac/Linux
venv\Scripts\activate       # Windows

pip install -r requirements.txt
```

```bash
MONGO_URI=mongodb+srv://<username>:<password>@cluster0.mongodb.net/lifesafe
JWT_SECRET_KEY=your_super_secure_jwt_secret_key
ADMIN_SECRET=your_admin_secret_key
GOOGLE_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
FRONTEND_ORIGIN=http://localhost:3000
PORT=5000
FLASK_DEBUG=1
```
```bash
flask run
```
