using System;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        try
        {
            using (ECDiffieHellmanCng ecdh = new ECDiffieHellmanCng())
            {
                byte[] publicKey = ecdh.PublicKey.ToByteArray();
                byte[] privateKey = ecdh.Key.Export(CngKeyBlobFormat.EccPrivateBlob);

                byte[] receivedPublicKey = publicKey;

                using (ECDiffieHellmanCng otherParty = new ECDiffieHellmanCng())
                {
                    ECDiffieHellmanPublicKey otherPartyPublicKey = ECDiffieHellmanCngPublicKey.FromByteArray(receivedPublicKey, CngKeyBlobFormat.EccPublicBlob);

                    byte[] sharedSecret = ecdh.DeriveKeyMaterial(otherPartyPublicKey);

                    //string plaintext = "Hello, world!";
                    string downloadsFolderPath = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + @"\Downloads";

                    string filePath = Path.Combine(downloadsFolderPath, "bundle fhir.txt");

                    if (!File.Exists(filePath))
                    {
                        Console.WriteLine("File not found: " + filePath);
                        return;
                    }

                    byte[] plaintextBytes = File.ReadAllBytes(filePath);
                    //byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);

                    using (Aes aes = new AesCryptoServiceProvider())
                    {
                        aes.Key = sharedSecret;
                        aes.GenerateIV();

                        byte[] iv = aes.IV;

                        using (var encryptor = aes.CreateEncryptor())
                        {
                            byte[] encryptedBytes = encryptor.TransformFinalBlock(plaintextBytes, 0, plaintextBytes.Length);

                            string encryptedBase64 = Convert.ToBase64String(encryptedBytes);
                            Console.WriteLine("Encrypt data: " + encryptedBase64);

                            using (var decryptor = aes.CreateDecryptor())
                            {
                                byte[] decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
                                string decryptedText = Encoding.UTF8.GetString(decryptedBytes);
                                Console.WriteLine("Decrypt data: " + decryptedText);
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message);
        }
    }
}
