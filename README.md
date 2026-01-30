# PhishEye.ai - Setup Instructions 🛡️

## 📁 Folder Structure

```
PhishEye-ai/
├── frontend/
│   ├── index.html
│   └── script.js
└── backend/
    └── app.py
```

---

## 🚀 Installation & Setup

### Step 1: Install Python Dependencies

Open Terminal/CMD and navigate to backend folder:

```bash
cd Desktop\PhishEye-ai\backend
pip install flask flask-cors requests reportlab
```

---

## ▶️ How to Run

### Terminal 1 - Start Backend

```bash
cd Desktop\PhishEye-ai\backend
python app.py
```

You should see:
```
============================================================
🛡️  PhishEye.ai - Fast & Upgraded
============================================================
✅ APIs: Active
✅ Link Scanner: Added
✅ Speed: Optimized (3-4s)
============================================================
🚀 http://localhost:5000
============================================================
```

**✅ Keep this terminal running!**

---

### Terminal 2 - Start Frontend

Open a NEW terminal/CMD window:

```bash
cd Desktop\PhishEye-ai\frontend
python -m http.server 8000
```

You should see:
```
Serving HTTP on 0.0.0.0 port 8000 ...
```

**✅ Keep this terminal running too!**

---

### Open in Browser

Go to:
```
http://localhost:8000
```

**That's it! 🎉**

---

## 🎯 Features

✅ **Multi-Type Scanner**
- URL Scanning
- Domain Analysis
- IP Address Check
- File Hash Verification
- **Link Scanner** (NEW!) - Detects suspicious link patterns
- Email Phishing Analysis

✅ **Mobile Responsive**
- Hamburger menu for mobile
- Touch-friendly interface

✅ **Reports Page**
- Download all scan reports as PDF
- View scan history
- Quick access to previous scans

✅ **Fast Scanning**
- Optimized to 3-4 seconds
- Real-time results

✅ **Persistent Data**
- Scan history saved in browser localStorage
- Data persists even after refresh

---

## 🛑 How to Stop

Press `Ctrl + C` in both terminals.

---

## 📱 Mobile Testing

1. Open browser DevTools (F12)
2. Click "Toggle Device Toolbar" (Ctrl+Shift+M)
3. Select a mobile device
4. See the hamburger menu in action!

---

## ⚠️ Troubleshooting

### "Module not found" error
```bash
pip install flask flask-cors requests reportlab
```

### Backend not connecting
- Make sure backend is running on port 5000
- Check firewall settings

### Frontend not loading
- Make sure you're in the `frontend` folder when running the server
- Try hard refresh: `Ctrl + Shift + R`

### Data not saving
- Check browser console (F12) for errors
- Make sure localStorage is enabled in browser settings
- Always use the same URL: `http://localhost:8000`

---

## 🔧 Tech Stack

- **Frontend**: HTML5, TailwindCSS, Vanilla JavaScript
- **Backend**: Python Flask, VirusTotal API, Groq AI
- **Storage**: Browser LocalStorage
- **PDF Generation**: ReportLab

---

## 📞 Support

If you face any issues:
1. Check both terminals are running
2. Clear browser cache (Ctrl + Shift + Delete)
3. Make sure ports 5000 and 8000 are not in use

---

**© 2026 PhishEye.ai - All Rights Reserved**
Powered by AI • Built for Security Professionals
