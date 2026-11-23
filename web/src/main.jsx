import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.jsx';
import './style.css';
import { storage, TOKEN_KEY } from './api.js';

if (import.meta.env.DEV && import.meta.env.MODE === 'mock') storage(s => s.setItem(TOKEN_KEY, 'demo-admin-token'));

createRoot(document.getElementById('root')).render(<StrictMode><App /></StrictMode>);
