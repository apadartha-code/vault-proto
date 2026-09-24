/**
  Copyright (C) 2026  https://github.com/apadartha-code

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://gnu.org>.
*/


/**
  //Gemini recommended polyfill for 2025 .toHex() for Uint8Array:

  if (!Uint8Array.prototype.toHex) {
  Uint8Array.prototype.toHex = function() {
    return Array.from(this, byte => byte.toString(16).padStart(2, '0')).join('');
  };
}
 */

export default class AppTranscoder {
  constructor(cryptoKey, rules) {
    this.key = cryptoKey;    // Must be an AES-GCM CryptoKey object
    this.rules = rules;      // Custom app metadata or configuration rules
    this.ivLength = 12;      // Standard secure IV length for AES-GCM is 12 bytes
    this.tagLengthBits = 128; // Standard and secure default for AES-GCM
  }

  // ==========================================
  // 1. BASE PAIR (Bytes <-> Base64)
  // ==========================================

  /**
   * Encrypts raw bytes (Uint8Array) using AES-GCM, prepends a unique IV,
   * and outputs a unified Base64 string.
   * @param {Uint8Array} rawBytes 
   * @returns {Promise<string>} Base64 encoded encrypted string
   */
  async encode(rawBytes) {
    // 1. Generate a fresh, securely random 12-byte IV for this specific operation
    const iv = window.crypto.getRandomValues(new Uint8Array(this.ivLength));

    // 2. Perform the AES-GCM encryption step
    const encryptedBuffer = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: iv,
        tagLength: this.tagLengthBits // Explicitly asking for a 128-bit tag
      },
      this.key,
      rawBytes
    );

    // 3. Combine the 12-byte IV header and the encrypted ciphertext bytes into one single array
    const encryptedBytes = new Uint8Array(encryptedBuffer);
    const combinedBuffer = new Uint8Array(iv.length + encryptedBytes.length);
    combinedBuffer.set(iv, 0);                        // Place IV at the beginning
    combinedBuffer.set(encryptedBytes, iv.length);    // Place ciphertext right after

    // 4. Convert the unified byte array into a Base64 string output
    return this._bytesToBase64(combinedBuffer);
  }

  /**
   * Decodes a composite Base64 string, strips the IV header, decrypts the 
   * payload via AES-GCM, and returns the raw plaintext bytes.
   * @param {string} base64Data 
   * @returns {Promise<Uint8Array>} Decrypted raw bytes
   */
  async decode(base64Data) {
    try {
      // 1. Convert the input Base64 string back into a raw byte array
      const combinedBuffer = this._base64ToBytes(base64Data);

      // 2. Structural sanity check: Must at least be longer than our 12-byte IV header
      if (combinedBuffer.length <= this.ivLength) {
        throw new Error("Ciphertext data payload is structurally invalid or truncated.");
      }

      // 3. Extract the 12-byte IV from the front of the array
      const iv = combinedBuffer.slice(0, this.ivLength);

      // 4. Extract the remaining bytes as the actual ciphertext payload
      const ciphertext = combinedBuffer.slice(this.ivLength);

      // 5. Decrypt using the extracted IV and the internal WebCrypto key
      const decryptedBuffer = await window.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: iv,
          tagLength: this.tagLengthBits // Explicitly asking for a 128-bit tag
        },
        this.key,
        ciphertext
      );

      return new Uint8Array(decryptedBuffer);

    } catch (error) {
      console.error("Transcoder decryption failed. Data may be corrupted or key is invalid:", error);
      // Return a zero-length byte array representation on failure
      return new Uint8Array(0);
    }
  }

  // ==========================================
  // 2. STRING VERSION (String <-> Base64)
  // ==========================================

  /**
   * Encrypts a plaintext string and returns a Base64 string.
   * @param {string} text 
   * @returns {Promise<string>} Base64 encoded encrypted string
   */
  async encode_str(text) {
    const textEncoder = new TextEncoder();
    const rawBytes = textEncoder.encode(text);
    return await this.encode(rawBytes);
  }

  /**
   * Decodes a Base64 string and recovers the original plaintext string.
   * @param {string} base64Data 
   * @returns {Promise<string>} Decrypted plaintext string
   */
  async decode_str(base64Data) {
    const decryptedBytes = await this.decode(base64Data);
    if (decryptedBytes.length === 0) return "";
    
    const textDecoder = new TextDecoder();
    return textDecoder.decode(decryptedBytes);
  }

  // ==========================================
  // 3. OBJECT VERSION (Object <-> Base64)
  // ==========================================

  /**
   * Encrypts any JSON-serializable data object and returns a Base64 string.
   * @param {any} obj 
   * @returns {Promise<string>} Base64 encoded encrypted string
   */
  async encode_obj(obj) {
    const jsonString = JSON.stringify(obj);
    return await this.encode_str(jsonString);
  }

  /**
   * Decodes a Base64 string and recovers the original data object.
   * @param {string} base64Data 
   * @returns {Promise<any|null>} Decrypted object or null if decryption failed/empty
   */
  async decode_obj(base64Data) {
    const jsonString = await this.decode_str(base64Data);
    if (!jsonString) return null;
    
    try {
      return JSON.parse(jsonString);
    } catch (error) {
      console.error("Transcoder JSON parsing failed:", error);
      return null;
    }
  }

  // ==========================================
  // INTERNAL HELPERS
  // ==========================================

  /**
   * Internal Helper: Converts a Uint8Array byte buffer to a standard Base64 string
   */
  _bytesToBase64(bytes) {
    const binString = Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");
    return btoa(binString);
  }

  /**
   * Internal Helper: Converts a standard Base64 string to a Uint8Array byte buffer
   */
  _base64ToBytes(base64String) {
    const binString = atob(base64String);
    return Uint8Array.from(binString, (m) => m.charCodeAt(0));
  }
}