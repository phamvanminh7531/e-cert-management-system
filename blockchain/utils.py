from Crypto.Hash import RIPEMD160, SHA256


def calculate_hash(data, hash_function: str = "sha256") -> str:
    data = bytearray(data, "utf-8")
    if hash_function == "sha256":
        h = SHA256.new()
        h.update(data)
        return h.hexdigest()
    if hash_function == "ripemd160":
        h = RIPEMD160.new()
        h.update(data)
        return h.hexdigest()

def verifyMerkleProof(txid, proof, root):
        
        sumHash = calculate_hash(txid)
        
        for hashNode in proof[:-1]:
            hash = hashNode[0]
            isLeft = hashNode[1]
            if isLeft:
                sumHash = calculate_hash(hash + sumHash)
            else:
                sumHash = calculate_hash(sumHash + hash)

        return sumHash == root