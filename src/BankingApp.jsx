import React, { useState, useEffect } from 'react';
import { Lock, User, DollarSign, Send, History, LogOut, Shield, Eye, EyeOff, AlertCircle } from 'lucide-react';
import './index.css';

// ===== Security Utilities =====
const SecurityUtils = {
  hashPassword: async (password, salt) => {
    const encoder = new TextEncoder();
    const data = encoder.encode(password + salt);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  },

  generateSalt: () => Math.random().toString(36).substring(2, 15),

  sanitizeInput: (input) =>
    input.replace(/[<>"'&]/g, (char) => {
      const escapeChars = {
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '&': '&amp;',
      };
      return escapeChars[char];
    }),

  validatePassword: (password) => {
    const minLength = 8;
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    return {
      valid: password.length >= minLength && hasUpper && hasLower && hasNumber && hasSpecial,
      requirements: {
        length: password.length >= minLength,
        uppercase: hasUpper,
        lowercase: hasLower,
        number: hasNumber,
        special: hasSpecial,
      },
    };
  },

  generateSessionToken: () =>
    Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, '0')).join(''),
};

// ===== Rate Limiter =====
class RateLimiter {
  constructor() {
    this.attempts = {};
    this.maxAttempts = 5;
    this.windowMs = 15 * 60 * 1000; // 15 minutes
  }

  checkLimit(identifier) {
    const now = Date.now();
    if (!this.attempts[identifier]) this.attempts[identifier] = [];

    // Clean old attempts
    this.attempts[identifier] = this.attempts[identifier].filter(time => now - time < this.windowMs);

    if (this.attempts[identifier].length >= this.maxAttempts) {
      return { allowed: false, remainingTime: Math.ceil((this.windowMs - (now - this.attempts[identifier][0])) / 1000 / 60) };
    }

    this.attempts[identifier].push(now);
    return { allowed: true, remainingAttempts: this.maxAttempts - this.attempts[identifier].length };
  }
}

// ===== BankingApp Component =====
const BankingApp = () => {
  const [currentView, setCurrentView] = useState('login');
  const [users, setUsers] = useState({});
  const [currentUser, setCurrentUser] = useState(null);
  const [session, setSession] = useState(null);
  const [showPassword, setShowPassword] = useState(false);
  const [rateLimiter] = useState(new RateLimiter());
  const [notification, setNotification] = useState(null);
  const [transactionLock, setTransactionLock] = useState(false);

  const [loginForm, setLoginForm] = useState({ username: '', password: '' });
  const [registerForm, setRegisterForm] = useState({ username: '', password: '', confirmPassword: '', initialDeposit: '1000' });
  const [transferForm, setTransferForm] = useState({ recipient: '', amount: '' });

  // Session timeout (5 minutes)
  useEffect(() => {
    if (session) {
      const timeout = setTimeout(() => {
        showNotification('Session expired. Please login again.', 'warning');
        handleLogout();
      }, 5 * 60 * 1000);
      return () => clearTimeout(timeout);
    }
  }, [session]);

  const showNotification = (message, type = 'info') => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 4000);
  };

  const handleKeyPress = (e, action) => {
    if (e.key === 'Enter') action();
  };

  // ===== Register =====
  const handleRegister = async () => {
    const { username, password, confirmPassword, initialDeposit } = registerForm;
    const sanitizedUsername = SecurityUtils.sanitizeInput(username.trim());

    if (!sanitizedUsername || sanitizedUsername.length < 3) {
      showNotification('Username must be at least 3 characters', 'error');
      return;
    }

    if (users[sanitizedUsername]) {
      showNotification('Username already exists', 'error');
      return;
    }

    const passwordValidation = SecurityUtils.validatePassword(password);
    if (!passwordValidation.valid) {
      showNotification('Password does not meet security requirements', 'error');
      return;
    }

    if (password !== confirmPassword) {
      showNotification('Passwords do not match', 'error');
      return;
    }

    const deposit = parseFloat(initialDeposit);
    if (isNaN(deposit) || deposit < 0) {
      showNotification('Invalid initial deposit amount', 'error');
      return;
    }

    const salt = SecurityUtils.generateSalt();
    const hashedPassword = await SecurityUtils.hashPassword(password, salt);

    const newUser = {
      username: sanitizedUsername,
      passwordHash: hashedPassword,
      salt: salt,
      balance: deposit,
      transactions: [],
      createdAt: new Date().toISOString(),
    };

    setUsers({ ...users, [sanitizedUsername]: newUser });
    showNotification('Account created successfully! Please login.', 'success');
    setCurrentView('login');
    setRegisterForm({ username: '', password: '', confirmPassword: '', initialDeposit: '1000' });
  };

  // ===== Login =====
  const handleLogin = async () => {
    const { username, password } = loginForm;
    const rateCheck = rateLimiter.checkLimit(username);
    if (!rateCheck.allowed) {
      showNotification(`Too many login attempts. Try again in ${rateCheck.remainingTime} minutes.`, 'error');
      return;
    }

    const sanitizedUsername = SecurityUtils.sanitizeInput(username.trim());
    const user = users[sanitizedUsername];

    if (!user) {
      showNotification('Invalid username or password', 'error');
      return;
    }

    const hashedAttempt = await SecurityUtils.hashPassword(password, user.salt);
    if (hashedAttempt !== user.passwordHash) {
      showNotification(`Invalid username or password. ${rateCheck.remainingAttempts} attempts remaining.`, 'error');
      return;
    }

    const sessionToken = SecurityUtils.generateSessionToken();
    const newSession = {
      token: sessionToken,
      username: sanitizedUsername,
      createdAt: Date.now(),
      expiresAt: Date.now() + 5 * 60 * 1000,
    };

    setSession(newSession);
    setCurrentUser(user);
    setCurrentView('dashboard');
    setLoginForm({ username: '', password: '' });
    showNotification(`Welcome back, ${sanitizedUsername}!`, 'success');
  };

  // ===== Transfer =====
  const handleTransfer = async () => {
    if (transactionLock) {
      showNotification('Another transaction is in progress. Please wait.', 'warning');
      return;
    }

    setTransactionLock(true);

    try {
      const { recipient, amount } = transferForm;
      const sanitizedRecipient = SecurityUtils.sanitizeInput(recipient.trim());
      const transferAmount = parseFloat(amount);

      if (!sanitizedRecipient) {
        showNotification('Please enter a recipient username', 'error');
        return;
      }

      if (isNaN(transferAmount) || transferAmount <= 0) {
        showNotification('Invalid transfer amount', 'error');
        return;
      }

      if (sanitizedRecipient === currentUser.username) {
        showNotification('Cannot transfer to yourself', 'error');
        return;
      }

      if (!users[sanitizedRecipient]) {
        showNotification('Recipient account not found', 'error');
        return;
      }

      if (currentUser.balance < transferAmount) {
        showNotification('Insufficient funds', 'error');
        return;
      }

      await new Promise(resolve => setTimeout(resolve, 500));

      const updatedUsers = { ...users };
      const sender = updatedUsers[currentUser.username];
      const recipientUser = updatedUsers[sanitizedRecipient];

      sender.balance -= transferAmount;
      recipientUser.balance += transferAmount;

      const transaction = {
        id: Date.now().toString(),
        type: 'transfer',
        from: sender.username,
        to: recipientUser.username,
        amount: transferAmount,
        timestamp: new Date().toISOString(),
      };

      sender.transactions.unshift(transaction);
      recipientUser.transactions.unshift({ ...transaction, type: 'received' });

      setUsers(updatedUsers);
      setCurrentUser(sender);
      setTransferForm({ recipient: '', amount: '' });
      showNotification(`Successfully transferred $${transferAmount.toFixed(2)} to ${sanitizedRecipient}`, 'success');
    } finally {
      setTransactionLock(false);
    }
  };

  // ===== Logout =====
  const handleLogout = () => {
    setSession(null);
    setCurrentUser(null);
    setCurrentView('login');
    showNotification('Logged out successfully', 'info');
  };

  // ===== Login View =====
  if (currentView === 'login') {
    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-indigo-900 flex items-center justify-center p-4">
        {notification && (
          <div className={`fixed top-4 right-4 p-4 rounded-lg shadow-lg ${
            notification.type === 'success' ? 'bg-green-500' :
            notification.type === 'error' ? 'bg-red-500' :
            notification.type === 'warning' ? 'bg-yellow-500' : 'bg-blue-500'
          } text-white max-w-md z-50`}>
            <div className="flex items-center gap-2">
              <AlertCircle size={20} />
              <span>{notification.message}</span>
            </div>
          </div>
        )}
        <div className="bg-white rounded-2xl shadow-2xl p-8 w-full max-w-md">
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-600 rounded-full mb-4">
              <Shield className="text-white" size={32} />
            </div>
            <h1 className="text-3xl font-bold text-gray-800">SecureBank</h1>
            <p className="text-gray-600 mt-2">Protected Banking System</p>
          </div>
          <div className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Username</label>
              <div className="relative">
                <User className="absolute left-3 top-3 text-gray-400" size={20} />
                <input
                  type="text"
                  value={loginForm.username}
                  onChange={(e) => setLoginForm({ ...loginForm, username: e.target.value })}
                  onKeyPress={(e) => handleKeyPress(e, handleLogin)}
                  className="w-full pl-10 pr-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Enter username"
                />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-3 text-gray-400" size={20} />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={loginForm.password}
                  onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })}
                  onKeyPress={(e) => handleKeyPress(e, handleLogin)}
                  className="w-full pl-10 pr-12 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  placeholder="Enter password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-3 text-gray-400 hover:text-gray-600"
                >
                  {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                </button>
              </div>
            </div>
            <button
              onClick={handleLogin}
              className="w-full bg-blue-600 text-white py-3 rounded-lg font-semibold hover:bg-blue-700 transition-colors"
            >
              Login
            </button>
          </div>
          <div className="mt-6 text-center">
            <button
              onClick={() => setCurrentView('register')}
              className="text-blue-600 hover:text-blue-700 font-medium"
            >
              Create New Account
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ===== Register View =====
  if (currentView === 'register') {
    const passwordValidation = SecurityUtils.validatePassword(registerForm.password);

    return (
      <div className="min-h-screen bg-gradient-to-br from-blue-900 via-blue-800 to-indigo-900 flex items-center justify-center p-4">
        {notification && (
          <div className={`fixed top-4 right-4 p-4 rounded-lg shadow-lg ${
            notification.type === 'success' ? 'bg-green-500' :
            notification.type === 'error' ? 'bg-red-500' :
            notification.type === 'warning' ? 'bg-yellow-500' : 'bg-blue-500'
          } text-white max-w-md z-50`}>
            <div className="flex items-center gap-2">
              <AlertCircle size={20} />
              <span>{notification.message}</span>
            </div>
          </div>
        )}

        <div className="bg-white rounded-2xl shadow-2xl p-8 w-full max-w-md">
          <div className="text-center mb-8">
            <h1 className="text-3xl font-bold text-gray-800">Create Account</h1>
            <p className="text-gray-600 mt-2">Join SecureBank today</p>
          </div>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Username</label>
              <input
                type="text"
                value={registerForm.username}
                onChange={(e) => setRegisterForm({ ...registerForm, username: e.target.value })}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Choose username (min 3 chars)"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Password</label>
              <input
                type={showPassword ? 'text' : 'password'}
                value={registerForm.password}
                onChange={(e) => setRegisterForm({ ...registerForm, password: e.target.value })}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Create strong password"
              />
              {registerForm.password && (
                <div className="mt-2 text-xs space-y-1">
                  <div className={passwordValidation.requirements.length ? 'text-green-600' : 'text-red-600'}>
                    {passwordValidation.requirements.length ? '✓' : '✗'} At least 8 characters
                  </div>
                  <div className={passwordValidation.requirements.uppercase ? 'text-green-600' : 'text-red-600'}>
                    {passwordValidation.requirements.uppercase ? '✓' : '✗'} One uppercase letter
                  </div>
                  <div className={passwordValidation.requirements.lowercase ? 'text-green-600' : 'text-red-600'}>
                    {passwordValidation.requirements.lowercase ? '✓' : '✗'} One lowercase letter
                  </div>
                  <div className={passwordValidation.requirements.number ? 'text-green-600' : 'text-red-600'}>
                    {passwordValidation.requirements.number ? '✓' : '✗'} One number
                  </div>
                  <div className={passwordValidation.requirements.special ? 'text-green-600' : 'text-red-600'}>
                    {passwordValidation.requirements.special ? '✓' : '✗'} One special character
                  </div>
                </div>
              )}
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Confirm Password</label>
              <input
                type={showPassword ? 'text' : 'password'}
                value={registerForm.confirmPassword}
                onChange={(e) => setRegisterForm({ ...registerForm, confirmPassword: e.target.value })}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="Confirm password"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Initial Deposit ($)</label>
              <input
                type="number"
                step="0.01"
                value={registerForm.initialDeposit}
                onChange={(e) => setRegisterForm({ ...registerForm, initialDeposit: e.target.value })}
                className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                placeholder="1000.00"
              />
            </div>

            <button
              onClick={handleRegister}
              className="w-full bg-blue-600 text-white py-3 rounded-lg font-semibold hover:bg-blue-700 transition-colors"
            >
              Create Account
            </button>
          </div>

          <div className="mt-6 text-center">
            <button
              onClick={() => setCurrentView('login')}
              className="text-blue-600 hover:text-blue-700 font-medium"
            >
              Back to Login
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ===== Dashboard View =====
  if (currentView === 'dashboard' && currentUser) {
    return (
      <div className="min-h-screen bg-gray-100 p-4">
        {notification && (
          <div className={`fixed top-4 right-4 p-4 rounded-lg shadow-lg ${
            notification.type === 'success' ? 'bg-green-500' :
            notification.type === 'error' ? 'bg-red-500' :
            notification.type === 'warning' ? 'bg-yellow-500' : 'bg-blue-500'
          } text-white max-w-md z-50`}>
            <div className="flex items-center gap-2">
              <AlertCircle size={20} />
              <span>{notification.message}</span>
            </div>
          </div>
        )}

        <div className="max-w-4xl mx-auto bg-white rounded-2xl shadow p-6 space-y-6">
          <div className="flex justify-between items-center">
            <h1 className="text-2xl font-bold text-gray-800">Dashboard</h1>
            <button
              onClick={handleLogout}
              className="flex items-center gap-2 bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700"
            >
              <LogOut size={18} /> Logout
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="p-4 border rounded-lg shadow-sm">
              <h2 className="font-semibold text-gray-700 mb-2">Account Balance</h2>
              <div className="text-3xl font-bold text-green-600">${currentUser.balance.toFixed(2)}</div>
            </div>

            <div className="p-4 border rounded-lg shadow-sm space-y-2">
              <h2 className="font-semibold text-gray-700 mb-2">Transfer Funds</h2>
              <input
                type="text"
                placeholder="Recipient username"
                value={transferForm.recipient}
                onChange={(e) => setTransferForm({ ...transferForm, recipient: e.target.value })}
                className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
              <input
                type="number"
                placeholder="Amount"
                value={transferForm.amount}
                onChange={(e) => setTransferForm({ ...transferForm, amount: e.target.value })}
                className="w-full px-4 py-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
              <button
                onClick={handleTransfer}
                disabled={transactionLock}
                className="w-full bg-blue-600 text-white py-2 rounded-lg font-semibold hover:bg-blue-700 transition-colors"
              >
                Send <Send size={16} className="inline-block ml-2" />
              </button>
            </div>
          </div>

          <div className="mt-4 p-4 border rounded-lg shadow-sm">
            <h2 className="font-semibold text-gray-700 mb-2">Transaction History</h2>
            {currentUser.transactions.length === 0 ? (
              <p className="text-gray-500">No transactions yet.</p>
            ) : (
              <ul className="space-y-2 max-h-64 overflow-y-auto">
                {currentUser.transactions.map(tx => (
                  <li key={tx.id} className="flex justify-between border-b pb-1">
                    <span>{tx.type === 'transfer' ? `Sent $${tx.amount.toFixed(2)} to ${tx.to}` : `Received $${tx.amount.toFixed(2)} from ${tx.from}`}</span>
                    <span className="text-gray-400 text-xs">{new Date(tx.timestamp).toLocaleString()}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>
    );
  }

  return null;
};

export default BankingApp;
