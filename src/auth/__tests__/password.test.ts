import { hashPassword, verifyPassword, validatePasswordStrength } from "../password";

describe("Password utilities", () => {
  describe("hashPassword", () => {
    it("should hash a password", async () => {
      const password = "SecurePass123!";
      const hash = await hashPassword(password);
      
      expect(hash).toBeDefined();
      expect(hash).not.toBe(password);
      expect(hash.length).toBeGreaterThan(0);
    });
    
    it("should generate different hashes for the same password", async () => {
      const password = "SecurePass123!";
      const hash1 = await hashPassword(password);
      const hash2 = await hashPassword(password);
      
      expect(hash1).not.toBe(hash2);
    });
  });
  
  describe("verifyPassword", () => {
    it("should verify a correct password", async () => {
      const password = "SecurePass123!";
      const hash = await hashPassword(password);
      
      const result = await verifyPassword(password, hash);
      
      expect(result).toBe(true);
    });
    
    it("should reject an incorrect password", async () => {
      const password = "SecurePass123!";
      const wrongPassword = "WrongPass456!";
      const hash = await hashPassword(password);
      
      const result = await verifyPassword(wrongPassword, hash);
      
      expect(result).toBe(false);
    });
  });
  
  describe("validatePasswordStrength", () => {
    it("should accept a strong password", () => {
      const result = validatePasswordStrength("SecurePass123!");
      
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
    
    it("should reject a short password", () => {
      const result = validatePasswordStrength("Abc1!");
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain("Password must be at least 8 characters");
    });
    
    it("should reject a password without uppercase", () => {
      const result = validatePasswordStrength("securepass123!");
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain("Password must contain at least one uppercase letter");
    });
    
    it("should reject a password without special characters", () => {
      const result = validatePasswordStrength("SecurePass123");
      
      expect(result.valid).toBe(false);
      expect(result.errors).toContain("Password must contain at least one special character");
    });
  });
});
