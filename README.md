# Academic Transcript Vault with NFT Access
A secure and decentralized way to store and share academic transcripts using NFT-based access control.

## 🌟 Features

- Store academic transcripts on-chain
- Issue NFT access keys for temporary transcript viewing
- Verify transcripts by authorized institutions
- Revoke access when needed

## 🔧 Usage

### For Institutions

1. Add a transcript:
```clarity
(contract-call? .academic-transcript-vault add-transcript "STUDENT123" "Transcript content here")
```

2. Verify a transcript:
```clarity
(contract-call? .academic-transcript-vault verify-transcript "STUDENT123")
```

3. Grant access:
```clarity
(contract-call? .academic-transcript-vault grant-access "STUDENT123" tx-sender u100)
```

### For Viewers

1. View transcript with access key:
```clarity
(contract-call? .academic-transcript-vault view-transcript u1)
```

## 🔐 Security

- Access is temporary and controlled via NFT ownership
- Only authorized institutions can add and verify transcripts
- Access can be revoked at any time

## 🚀 Getting Started

1. Clone the repository
2. Deploy using Clarinet
3. Test with included test cases

## 📝 License

MIT
```
