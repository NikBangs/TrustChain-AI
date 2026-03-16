# TrustChain AI

A browser extension and backend service that evaluates website trustworthiness using AI-powered analysis. TrustChain AI helps users identify potentially fraudulent or suspicious e-commerce websites by analyzing multiple security signals.

## Features

- **Multi-factor Trust Scoring**: Evaluates websites based on:
  - Domain reputation (age, blacklist status, TLD analysis)
  - User sentiment (Reddit, Trustpilot analysis)
  - Payment security (gateway reputation, scam reports)
  - Technical behavior (malware indicators, suspicious patterns)
  - Business legitimacy (legal pages, contact information)

- **Real-time Analysis**: Chrome extension that provides instant trust scores for any website

- **Comprehensive Logging**: Tracks all evaluations with detailed criteria breakdowns

## Project Structure

```
TrustChain AI/
├── backend/              # Flask API server
│   ├── app.py           # Main Flask application
│   ├── scorer.py        # Trust scoring logic
│   ├── utils.py         # Utility functions (API integrations)
│   ├── logger.py        # Logging utilities
│   └── requirements.txt # Python dependencies
├── extension/           # Chrome extension
│   ├── manifest.json    # Extension manifest
│   ├── popup.html       # Popup UI
│   ├── popup.js         # Popup logic
│   ├── content.js       # Content script
│   ├── background.js    # Background service worker
│   └── icon.png         # Extension icon
└── smart-contract/      # (legacy) Ethereum smart contract (no longer required)
```

## Setup

### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Create a `.env` file in the `backend/` directory with the following variables:
   ```env
   # API Keys
   WHOIS_API_KEY=your_whois_api_key
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   PERPLEXITY_API=your_perplexity_api_key
   
   # Reddit API (optional)
   REDDIT_CLIENT_ID=your_reddit_client_id
   REDDIT_CLIENT_SECRET=your_reddit_client_secret
   REDDIT_USER_AGENT=your_reddit_user_agent
   
   # (Legacy) Blockchain Configuration - no longer required
   # RPC=your_ethereum_rpc_url
   # CONTRACT_ADDRESS=your_contract_address
   # PRIVATE_KEY=your_private_key
   ```

5. Run the Flask server:
   ```bash
   python app.py
   ```
   The server will start on `http://localhost:5000`

### Extension Setup

1. Open Chrome and navigate to `chrome://extensions/`

2. Enable "Developer mode" (toggle in top right)

3. Click "Load unpacked" and select the `extension/` directory

4. The TrustChain AI extension icon should appear in your toolbar

### Smart Contract Setup

1. Navigate to the smart-contract directory:
   ```bash
   cd smart-contract
   ```

2. Install Node.js dependencies:
   ```bash
   npm install
   ```

3. Deploy the contract (after configuring Hardhat):
   ```bash
   npx hardhat run scripts/deploy.js --network <your-network>
   ```

## API Endpoints

- `POST /evaluate` - Evaluate a website's trustworthiness
  - Body: `{ "domain": "example.com", "content": "page content..." }`
  - Returns: `{ "trust_score": 85, "risk": "safe", "flagged": false, "criteria": {...} }`

- `POST /report` - Report a suspicious website to the backend logging system
  - Body: `{ "domain": "suspicious-site.com" }`
  - Returns: `{ "status": "logged", "tx": "0x..." }`

- `GET /logs` - Get recent evaluation logs
  - Returns: Array of recent evaluation entries

## Trust Score Breakdown

The trust score (0-100) is calculated from five categories (20 points each):

- **Domain Reputation (20 pts)**: Domain age, blacklist status, TLD analysis
- **User Sentiment (20 pts)**: Reddit posts, Trustpilot reviews, social media mentions
- **Payment Security (20 pts)**: Payment gateway reputation, scam reports, checkout security
- **Technical Behavior (20 pts)**: Malware indicators, suspicious patterns, redirects
- **Business Legitimacy (20 pts)**: Legal pages, contact information, refund policies

**Risk Levels:**
- 80-100: Safe
- 50-79: Suspicious
- 0-49: High Risk

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `WHOIS_API_KEY` | WhoisXML API key for domain age checking | Yes |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key for blacklist checking | Yes |
| `PERPLEXITY_API` | Perplexity AI API key for payment analysis | Yes |
| `REDDIT_CLIENT_ID` | Reddit API client ID | No |
| `REDDIT_CLIENT_SECRET` | Reddit API client secret | No |
| `REDDIT_USER_AGENT` | Reddit API user agent | No |
| `RPC` | Ethereum RPC endpoint URL (legacy, no longer used) | No |
| `CONTRACT_ADDRESS` | Deployed TrustChain contract address (legacy, no longer used) | No |
| `PRIVATE_KEY` | Ethereum private key for transactions (legacy, no longer used) | No |

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the ISC License - see the LICENSE file for details.

## Security Note

⚠️ **Important**: Never commit your `.env` file or expose your private keys. The `.gitignore` file is configured to exclude sensitive files, but always double-check before committing.
