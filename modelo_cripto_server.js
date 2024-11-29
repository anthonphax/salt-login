const crypto = require("crypto");

// Adicione uma chave de criptografia AES-256-GCM
const AES_KEY = Buffer.from("0123456789abcdef0123456789abcdef", "utf-8"); // Substitua por sua chave de 32 bytes

// Password reset endpoint com suporte a AES
app.post("/reset-password", (req, res) => {
    const { iv, ciphertext } = req.body;

    if (!iv || !ciphertext) {
        return res.status(400).json({ error: "IV and ciphertext are required" });
    }

    try {
        // Descriptografar os dados recebidos
        const decipher = crypto.createDecipheriv("aes-256-gcm", AES_KEY, Buffer.from(iv, "hex"));
        const decrypted = Buffer.concat([
            decipher.update(Buffer.from(ciphertext, "hex")),
            decipher.final(),
        ]);

        // Converter o resultado para JSON
        const { username, newPassword } = JSON.parse(decrypted.toString());

        if (!username || !newPassword) {
            return res.status(400).json({ error: "Username and new password are required" });
        }

        // Hash the new password
        bcrypt.hash(newPassword, saltRounds, (err, hash) => {
            if (err) return res.status(500).json({ error: "Error hashing new password" });

            // Update user password and reset revoked status
            db.run(
                `UPDATE users SET password = ?, revoked = 0 WHERE username = ?`,
                [hash, username],
                function (err) {
                    if (err) return res.status(500).json({ error: "Database error" });
                    if (this.changes === 0) return res.status(404).json({ error: "User not found" });
                    res.status(200).json({ message: "Password reset successfully!" });
                }
            );
        });
    } catch (error) {
        console.error("Decryption error:", error);
        res.status(400).json({ error: "Invalid encrypted data" });
    }
});
