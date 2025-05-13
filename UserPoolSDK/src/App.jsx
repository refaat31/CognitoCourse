import { useState, useEffect } from 'react'
import { Amplify } from 'aws-amplify';
import { 
  signIn, 
  signOut,
  confirmSignIn,
  getCurrentUser,
  fetchDevices,
  rememberDevice,
  forgetDevice
} from 'aws-amplify/auth';
import './App.css'

// Configure Amplify
const poolId = import.meta.env.VITE_USER_POOL_ID;
const clientId = import.meta.env.VITE_CLIENT_ID;

Amplify.configure({
  Auth: {
    Cognito: {
      userPoolId: poolId,
      userPoolClientId: clientId,
      signUpVerificationMethod: 'code',
      loginWith: {
        email: true,
      },
      mfa: {
        status: 'on',
        totpEnabled: true,
        smsEnabled: false,
      },
      passwordFormat: {
        minLength: 8,
      }
    }
  }
});

function App() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [view, setView] = useState("login");
  const [rememberDevice, setRememberDevice] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [user, setUser] = useState(null);
  const [newPassword, setNewPassword] = useState("");

  // Add security configurations
  const [deviceTrustDuration, setDeviceTrustDuration] = useState(30); // days
  const [showSecurityWarning, setShowSecurityWarning] = useState(false);

  useEffect(() => {
    // Check if user is already signed in
    checkUser();
    // Debug: Check device storage
    checkDeviceStorage();
  }, []);

  const checkUser = async () => {
    try {
      const currentUser = await getCurrentUser();
      setUser(currentUser);
      console.log('Current user:', currentUser);
    } catch (error) {
      console.log('No user signed in');
    }
  };

  const checkDeviceStorage = () => {
    // Debug: Show all localStorage keys related to Cognito
    console.log('=== Device Storage Debug ===');
    const cognitoKeys = Object.keys(localStorage).filter(key => 
      key.includes('aws') || key.includes('cognito') || key.includes('device')
    );
    
    cognitoKeys.forEach(key => {
      console.log(`${key}:`, localStorage.getItem(key));
    });
    
    // Specifically look for device keys
    const deviceKeys = Object.keys(localStorage).filter(key => 
      key.includes('deviceKey') || key.includes('DeviceKey')
    );
    console.log('Device Keys found:', deviceKeys);
    
    // Check if device credentials exist
    if (deviceKeys.length > 0) {
      console.warn('⚠️ Device credentials are stored in localStorage - ensure this device is secure');
    }
  };

  const handleLogin = async () => {
    setLoading(true);
    setError("");
    
    try {
      // Debug: Check device info before login
      console.log('=== Before Login ===');
      checkDeviceStorage();
      
      const { isSignedIn, nextStep } = await signIn({ 
        username: email,
        password: password,
        options: {
          authFlowType: 'USER_SRP_AUTH'
        }
      });

      console.log('Sign in response:', { isSignedIn, nextStep });

      if (isSignedIn) {
        alert("Login Successful!");
        console.log('MFA was skipped - device was recognized!');
        await checkUser();
        resetForm();
      } else {
        console.log('MFA required - device not recognized or not remembered');
        handleNextStep(nextStep);
      }
    } catch (error) {
      console.error("Login error:", error);
      setError(error.message || "Login failed. Please check your credentials.");
    } finally {
      setLoading(false);
    }
  };

  const handleNextStep = (nextStep) => {
    switch (nextStep.signInStep) {
      case 'CONFIRM_SIGN_IN_WITH_TOTP_CODE':
        setView('mfa');
        break;
      case 'CONFIRM_SIGN_IN_WITH_NEW_PASSWORD_REQUIRED':
        setView('newPassword');
        break;
      case 'CONFIRM_SIGN_IN_WITH_CUSTOM_CHALLENGE':
        setView('mfa');
        break;
      case 'CONTINUE_SIGN_IN_WITH_MFA_SETUP':
        setError('MFA setup required. Please set up MFA in your account settings.');
        break;
      default:
        console.log('Unhandled next step:', nextStep);
    }
  };

  const handleMFAChallenge = async () => {
    setLoading(true);
    setError("");
    
    try {
      const { isSignedIn, nextStep } = await confirmSignIn({
        challengeResponse: otp
      });

      console.log('MFA confirmation result:', { isSignedIn, nextStep });

      if (isSignedIn) {
        alert("Login Successful!");
        
        // Handle device remembering
        if (rememberDevice) {
          try {
            await rememberDevice();
            console.log('Device remembered successfully');
            
            // Debug: Check what device info was stored
            setTimeout(() => {
              console.log('=== After Device Remember ===');
              checkDeviceStorage();
            }, 1000);
          } catch (error) {
            console.error('Error remembering device:', error);
          }
        }
        
        await checkUser();
        resetForm();
      } else {
        handleNextStep(nextStep);
      }
    } catch (error) {
      console.error("MFA error:", error);
      setError("Invalid OTP. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleNewPasswordChallenge = async () => {
    setLoading(true);
    setError("");
    
    try {
      const { isSignedIn, nextStep } = await confirmSignIn({
        challengeResponse: newPassword
      });

      console.log('New password result:', { isSignedIn, nextStep });
      
      if (isSignedIn) {
        alert("Password changed successfully!");
        await checkUser();
        resetForm();
      } else {
        handleNextStep(nextStep);
      }
    } catch (error) {
      console.error("Password change error:", error);
      setError("Failed to change password. Please ensure it meets requirements.");
    } finally {
      setLoading(false);
    }
  };

  const handleSignOut = async () => {
    try {
      await signOut();
      setUser(null);
      setView('login');
      console.log('Signed out successfully');
    } catch (error) {
      console.error('Error signing out:', error);
    }
  };

  const resetForm = () => {
    setEmail("");
    setPassword("");
    setOtp("");
    setNewPassword("");
    setRememberDevice(false);
    setView('login');
    setError("");
  };

  const viewRememberedDevices = async () => {
    try {
      const devices = await fetchDevices();
      console.log('Remembered devices:', devices);
      alert(`You have ${devices.length} remembered device(s). Check console for details.`);
    } catch (error) {
      console.error('Error fetching devices:', error);
    }
  };

  const forgetThisDevice = async () => {
    try {
      await forgetDevice();
      alert('This device has been forgotten. MFA will be required on next login.');
      // Clear local device credentials
      const cognitoKeys = Object.keys(localStorage).filter(key => 
        key.includes('deviceKey') || key.includes('DeviceKey')
      );
      cognitoKeys.forEach(key => localStorage.removeItem(key));
    } catch (error) {
      console.error('Error forgetting device:', error);
    }
  };

  const clearAllDevices = () => {
    // Clear all Cognito-related data from localStorage
    const cognitoKeys = Object.keys(localStorage).filter(key => 
      key.includes('aws-amplify') || key.includes('CognitoIdentityServiceProvider')
    );
    cognitoKeys.forEach(key => localStorage.removeItem(key));
    alert('All device credentials cleared. MFA will be required on next login.');
  };

  // Show logged in view if user is authenticated
  if (user) {
    return (
      <div className='card'>
        <h3>Welcome, {user.username}!</h3>
        <p>You are successfully logged in.</p>
        <div style={{ marginTop: '20px' }}>
          <button onClick={viewRememberedDevices} style={{ marginRight: '10px' }}>
            View Remembered Devices
          </button>
          <button onClick={forgetThisDevice} style={{ marginRight: '10px' }}>
            Forget This Device
          </button>
          <button onClick={clearAllDevices} style={{ marginRight: '10px' }}>
            Clear All Devices
          </button>
          <button onClick={handleSignOut}>Sign Out</button>
        </div>
        <div style={{ marginTop: '20px', fontSize: '0.9em', color: '#666' }}>
          <p>⚠️ Security Note: Device credentials are stored locally. Only remember devices you trust.</p>
        </div>
      </div>
    );
  }

  if (view === "login") {
    return (
      <div className='card'>
        <h3>Login</h3>
        {error && <div style={{ color: 'red', marginBottom: '10px' }}>{error}</div>}
        <input 
          placeholder='Enter email' 
          value={email} 
          onChange={e => setEmail(e.target.value)} 
          style={{ marginBottom: '10px' }}
        />
        <input 
          placeholder='Enter password' 
          type="password" 
          value={password} 
          onChange={e => setPassword(e.target.value)}
          style={{ marginBottom: '10px' }}
        />
        <br />
        <button onClick={handleLogin} disabled={loading}>
          {loading ? 'Loading...' : 'Login'}
        </button>
      </div>
    )
  }
  else if (view === "newPassword") {
    return (
      <div className='card'>
        <h3>Change Password</h3>
        {error && <div style={{ color: 'red', marginBottom: '10px' }}>{error}</div>}
        <p>You must change your password to continue.</p>
        <input 
          placeholder='Enter new password' 
          type="password" 
          value={newPassword} 
          onChange={e => setNewPassword(e.target.value)}
          style={{ marginBottom: '10px' }}
        />
        <br />
        <button onClick={handleNewPasswordChallenge} disabled={loading}>
          {loading ? 'Saving...' : 'Save New Password'}
        </button>
      </div>
    )
  }
  else if (view === "mfa") {
    return (
      <div className='card'>
        <h3>Enter MFA Code</h3>
        {error && <div style={{ color: 'red', marginBottom: '10px' }}>{error}</div>}
        <input 
          placeholder='Enter 6-digit code' 
          value={otp} 
          onChange={e => setOtp(e.target.value)}
          maxLength="6"
          style={{ marginBottom: '10px' }}
        />
        <br />
        <label style={{ display: 'block', marginBottom: '10px' }}>
          <input 
            type="checkbox" 
            checked={rememberDevice} 
            onChange={e => {
              setRememberDevice(e.target.checked);
              if (e.target.checked) {
                setShowSecurityWarning(true);
              }
            }}
          />
          Remember this device (skip MFA next time)
        </label>
        {showSecurityWarning && rememberDevice && (
          <div style={{ 
            backgroundColor: '#fff3cd', 
            border: '1px solid #ffeaa7',
            padding: '10px',
            marginBottom: '10px',
            borderRadius: '4px',
            fontSize: '0.9em'
          }}>
            ⚠️ <strong>Security Warning:</strong> Only remember trusted devices. Anyone with access to this device could potentially bypass MFA.
          </div>
        )}
        <br />
        <button onClick={handleMFAChallenge} disabled={loading}>
          {loading ? 'Verifying...' : 'Verify Code'}
        </button>
      </div>
    )
  }

  // This should never happen, but just in case
  return <div>Loading...</div>;
}

export default App