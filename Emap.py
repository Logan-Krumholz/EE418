import random

def generateRandomString(k):
    return ''.join(str(random.randint(0, 1)) for _ in range(k))

def band(str1, str2, k):
    return bin((int(str1, 2) & int(str2, 2)) % (2 ** k))[2:].zfill(k)

def bor(str1, str2, k):
    return bin((int(str1, 2) | int(str2, 2)) % (2 ** k))[2:].zfill(k)

def bxor(str1, str2, k):
    return bin((int(str1, 2) ^ int(str2, 2)) % (2 ** k))[2:].zfill(k)

def Fp(x):
    result = ""
    for i in range(0, len(x), 4):
        block = x[i:i+4]
        xor_result = int(block[0])
        for bit in block[1:]:
            xor_result ^= int(bit)
        result += str(xor_result)
    return result

class EMAPoracle:
    def __init__(self, k, IDP, ID, K1, K2, K3, K4):
        self.k = k
        self.IDP = IDP
        self.ID = ID
        self.K1 = K1
        self.K2 = K2
        self.K3 = K3
        self.K4 = K4

    def protocolRun(self):
        n1 = generateRandomString(self.k)
        n2 = generateRandomString(self.k)

        A = bxor(bxor(self.IDP, self.K1, self.k), n1, self.k)
        B = bxor(bor(self.IDP, self.K2, self.k), n1, self.k)
        C = bxor(bxor(self.IDP, self.K3, self.k), n2, self.k)

        # Debugging print statements
        print(f"Generated n1: {n1}, n2: {n2}")
        print(f"Calculated A: {A}, B: {B}, C: {C}")

        computed_n1 = bxor(bxor(A, self.IDP, self.k), self.K1, self.k)
        computed_n2 = bxor(bxor(C, self.IDP, self.k), self.K3, self.k)

        expected_B = bxor(bor(self.IDP, self.K2, self.k), n1, self.k)

        print(f"Computed n1: {computed_n1}, n2: {computed_n2}")
        print(f"Expected B: {expected_B}, Actual B: {B}")

        if B == expected_B:
            D = bxor(band(self.IDP, self.K4, self.k), computed_n2, self.k)
            E = bxor(bxor(bor(band(self.IDP, n1, self.k), n2, self.k), self.ID, self.k), 
                     bxor(bxor(self.K1, self.K2, self.k), bxor(self.K3, self.K4, self.k), self.k), self.k)

            # Update keys
            ID1_48 = self.ID[:self.k // 2] 
            ID49_96 = self.ID[self.k // 2:]
            self.IDP = bxor(self.IDP, bxor(n2, self.K1, self.k), self.k)
            self.K1 = bxor(self.K1, bxor(n2, ID1_48 + Fp(self.K4) + Fp(self.K3), self.k), self.k)
            self.K2 = bxor(self.K2, bxor(n2, Fp(self.K1) + Fp(self.K4) + ID49_96, self.k), self.k)
            self.K3 = bxor(self.K3, bxor(n1, ID1_48 + Fp(self.K4) + Fp(self.K2), self.k), self.k)
            self.K4 = bxor(self.K4, bxor(n1, Fp(self.K3) + Fp(self.K1) + ID49_96, self.k), self.k)

            return {'A': A, 'B': B, 'C': C, 'D': D, 'E': E}, self
        else:
            
            return None, self

    def verifyID(self, given_ID):
        return self.ID == given_ID

# Test
k = 4  
IDP = generateRandomString(k)
ID = generateRandomString(k)
K1 = generateRandomString(k)
K2 = generateRandomString(k)
K3 = generateRandomString(k)
K4 = generateRandomString(k)

emap_oracle = EMAPoracle(k, IDP, ID, K1, K2, K3, K4)
protocol_output, updated_oracle = emap_oracle.protocolRun()

if protocol_output:
    print("Protocol Output:", protocol_output)
    is_id_correct = updated_oracle.verifyID(ID)
    print("Verified:", is_id_correct)
else:
    print("Authentication failed during the protocol run.")
