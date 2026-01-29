// Firebase Configuration for NetMonitoring
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.7.1/firebase-app.js";
import { getAuth } from "https://www.gstatic.com/firebasejs/10.7.1/firebase-auth.js";
import { getDatabase } from "https://www.gstatic.com/firebasejs/10.7.1/firebase-database.js";

// Firebase config - same database as netmonitor
const firebaseConfig = {
  apiKey: "AIzaSyDf1YTfTkyA_3-Lxs4fGjNgCy6yHgkz69w",
  authDomain: "netmotinor.firebaseapp.com",
  databaseURL: "https://netmotinor-default-rtdb.asia-southeast1.firebasedatabase.app",
  projectId: "netmotinor",
  storageBucket: "netmotinor.firebasestorage.app",
  messagingSenderId: "168521329016",
  appId: "1:168521329016:web:961b80d644938450b8c08d"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const database = getDatabase(app);

export { app, auth, database };
