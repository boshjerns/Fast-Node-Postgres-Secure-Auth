const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const certsDir = path.join(__dirname, '..', 'certs');

// Create certs directory if it doesn't exist
if (!fs.existsSync(certsDir)) {
  fs.mkdirSync(certsDir, { recursive: true });
}

try {
  console.log('Generating self-signed SSL certificates for development...');
  
  // Generate private key
  execSync(`openssl genrsa -out ${path.join(certsDir, 'private-key.pem')} 2048`, { stdio: 'inherit' });
  
  // Generate certificate
  execSync(`openssl req -new -x509 -key ${path.join(certsDir, 'private-key.pem')} -out ${path.join(certsDir, 'certificate.pem')} -days 365 -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"`, { stdio: 'inherit' });
  
  console.log('SSL certificates generated successfully!');
  console.log(`Private key: ${path.join(certsDir, 'private-key.pem')}`);
  console.log(`Certificate: ${path.join(certsDir, 'certificate.pem')}`);
  console.log('\nNote: These are self-signed certificates for development only.');
  console.log('Your browser will show a security warning. You can safely proceed for development.');
  
} catch (error) {
  console.error('Error generating SSL certificates:', error.message);
  console.log('\nOpenSSL is required to generate certificates.');
  console.log('On Windows: Install OpenSSL or use WSL');
  console.log('On macOS: Install with `brew install openssl`');
  console.log('On Linux: Install with your package manager (e.g., `apt install openssl`)');
  process.exit(1);
} 