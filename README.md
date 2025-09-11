# Farewell       
<p align="center"> <img src="assets/farewell-logo.png" alt="Farewell Logo" width="600"/> </p>

**Farewell** is a decentralized application (dApp) that allows people to leave **posthumous encrypted messages** to their loved ones.  
It uses **smart contracts** built on top of the [fhevm](https://github.com/zama-ai/fhevm) to securely store encrypted data, enforce liveness checks, and release messages only after a configurable timeout.

Because it is deployed as a smart contract on Ethereum, **Farewell inherits the reliability and persistence of decentralized infrastructure**. This means the system is designed so that it will keep functioning for decades without depending on a single server or authority, and messages cannot be lost or tampered with once stored.

We have a **live demo** as [proof of concept](https://www.iampedro.com/farewell) running on Sepolia.

---

## ✨ Features

- **Check-in mechanism**:  
    Each user sets a `checkInPeriod` (e.g., 6 months) and must periodically call `ping()` to prove liveness.
    
- **Grace period**:  
    After the `checkInPeriod` expires, a `gracePeriod` allows for unexpected delays before a user is marked deceased. During this period, a selected **council** can intervene, either by ensuring liveness (equivalent to a `ping()` call) or by asserting death. After this period, if no council action is received, the user is assumed to have passed away and can be marked as deceased.
    
- **Deceased flagging**:  
    If the user does not check in during both periods, anyone may call `markDeceased()` to change the user’s status.
    
- **Encrypted messages**:  
    Users can upload encrypted messages with associated recipients.  Messages contain:
    
    - Encrypted message data (treated as locally-encrypted ciphertext)

    - Encrypted recipient’s email (stored as an `euint`, remaining hidden until revealed)
        
    - A private share of the user’s decryption key (also stored as an `euint`)
        
- **Delivery mechanism**:  
    After the user is flagged as deceased:
    
    - Anyone may call `claim()` to mark a message as ready for release. The address that initially marked the user as deceased has a 24-hour priority window for claiming a message.
        
    - Recipients (or external services) can then call `retrieve()` (view) to obtain a **DeliveryPackage** containing:
        
        - Recipient’s email address
            
        - The (hopefully) encrypted message
            
        - The key share
            
- **Blockchain persistence**:  
    Running entirely as a smart contract on Ethereum (or other similar chains in the future), **Farewell ensures the system operates reliably for decades** without reliance on a central operator, and that **messages cannot be lost once stored**.
    

---

## 🔒 Securing messages

Messages are stored on the blockchain, so it is **strongly recommended** that they be locally encrypted before submission. If submitted in cleartext, they become immediately publicly visible. 

The recipient contact, on the other hard, is stored in fhEVM and thus requires no additional protection. The Zama Protocol will ensure it stays private until the message is released, and only becomes visible to those authorized to deliver it. The same applies for the secret key share.

This design ensures that the system is **fully private** while still revealing the necessary information to deliver messages at the right time.

---

## 🔑 The share of the secret key

Since the message must be encrypted client-side, the recipient needs a mechanism to enable decryption after the user is deceased. This mechanism is the **secret key share**.

While alive, the user may choose to share the decryption key directly with the recipient, making them aware of the secure payload to be recovered after death. In that case, the secret key share would be empty, and the recipient would hold the full key.

This approach, however, may draw unwanted attention. Because the payload is stored on-chain, a recipient who already has the full key could retrieve and decrypt it prematurely.

An alternative would be to store the entire decryption key as the “share.” This requires no interaction with the recipient and prevents **anyone** from decrypting the message beforehand. However, once released, **any retriever** could decrypt it, including unintended parties, which creates a privacy risk.

Our recommendation is a middle ground. 

Suppose the user encrypts their message using AES-128. Let `sk` be the AES secret key, and `s` a randomly sampled 128-bit integer. The user computes:

`s' = sk ⊕ s`,

then stores `s` as the secret key share in fhEVM, and shares `s'` with the recipient.

When the time comes, Farewell releases `enc_sk(m)` (the encryption of message `m` under `sk`) and `s'`. The recipient computes `sk = s ⊕ s'` and then decrypts the ciphertext.

This guarantees the recipient cannot decrypt the message before the time, and that only they will be able to do so.

---

## ⚠️ Notes & Limitations

- The message **must be encrypted client-side** before being stored on-chain. We recommend [GPG](https://gnupg.org/) for encryption.
    
- To **save gas costs**, messages should be **compacted** before submission (e.g., archived and compressed with `tar` + `gzip`).
    
- On-chain data is **public**.
    
    - Submitted messages are publicly visible. This is why they must be pre-encrypted client-side.
        
    - Key shares are stored as **encrypted integers (`euint`)**, remaining hidden until released.
        
- This is a **Proof-of-Concept** only.  
    Not production-ready; there are no guarantees of security, privacy, or delivery.
    
---

## 🚀 Usage

### Test and Deploy

```bash
npx hardhat compile
npx hardhat test
npx hardhat deploy --network <network>
```

### Interact

In Hardhat console:

```bash
npx hardhat console --network <network>
```

---

## 🔐 Workflow

### 1. User registers

- Defines `checkInPeriod` + `gracePeriod`
    

### 2. User adds messages

- Each message contains recipient email, encrypted message, and the secret key share
    

### 3. User stays alive

- Calls `ping()` periodically
    

### 4. Timeout occurs

- Anyone may call `markDeceased()`
    

### 5. Messages are claimed and retrieved

- `claim()` marks the message as ready and temporary enables the caller to retrieve it
    
- `retrieve()` (view) returns a **DeliveryPackage**:  
    `(recipientEmail, ciphertext, keyShare)`
    
- Off-chain system delivers and decrypts messages
    

---

## 📊 Sequence Diagrams

🚧 todo 🚧

---

## 🔧 Encrypting & Compacting Data

All data stored on-chain should be **encrypted and compacted** to reduce storage costs and keep confidentiality.

### Encrypt and Compact

```bash
# Encrypt with GPG
gpg --symmetric --cipher-algo AES256 message.txt

# Pack + compress the encrypted file
tar -czf message.tar.gz message.txt.gpg
```

### Hex-encode for Contract Submission

```bash
# Encode to hex (Linux/Unix)
xxd -p message.tar.gz | tr -d '\n' > message.hex
```

Now you can pass the contents of `message.hex` (prefixed with `0x`) to `addMessage()`.

Example:

```js
await Farewell.addMessage("alice@example.com", "0x" + hexString);
```

### Recover Message

```bash
# Decode from hex
xxd -r -p message.hex > message.tar.gz

# Extract the archive
tar -xzf message.tar.gz

# Decrypt with GPG
gpg --decrypt message.txt.gpg
```

---

## 🔮 Future work

Farewell is **not** feature complete. It needs:

- **Proof of email delivery**:  
    By integrating [zk.email](https://docs.zk.email/architecture/on-chain), the message retriever could prove on-chain that the encrypted message was actually submitted to the intended recipient. 
    This would allow `retrieve()` not only to release a DeliveryPackage but also to **reward the claimer** once they provide a valid delivery proof.
    
- **Council logic**:
    A council could be set up to intervene in case of unexpected delays during the grace period. The user would define this council at registration via wallet addresses.  Council members could act when the check-in period expires, either to ensure the user is alive or to confirm death and enable message retrieval.
    
- **Edit messages**:
    Users may change their minds (while still alive). Farewell should support withdrawing or editing Perfect — here’s the revised Open Issues section with a clear definition of secure and GitHub issue links you can point to (I’ll use placeholders you can replace with real issue numbers or URLs):

---

## 🧩 Open Issues

In the context of Farewell, secure means:
	•	The message remains unreadable until the user’s death.
	•	Once released, only the intended recipient can decrypt and read it.

Several design questions remain open to reach this level of security:

### On-chain secrecy without external protocols
Is it possible to store and release encrypted key shares purely on-chain (without depending on Zama Protocol or external coprocessors) while keeping data secret until release?
👉 [Discussion on GitHub](https://github.com/pdroalves/farewell-core/issues/1)

### Reliable delivery protocol
How can we define a delivery protocol that is:
	•	Friendly to delivery proofs (e.g., zk.email-style attestations)
	•	Potentially better than emails in terms of reliability, privacy, and censorship resistance
👉 Discussion on GitHub

Community input and experimentation are welcome.

---

## 📜 License

MIT
