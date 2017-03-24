# leakage resistant crypto implementation


from Crypto.Hash import SHA

# substution polynomials for x^16 to x^30

subpolys = [
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20],  # x16
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0],  # x17
[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0, 0],  # x18
[0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0, 0, 0],  # x19
[0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0, 0, 0, 0],  # x20
[0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0, 0, 0, 0, 0],  # x21
[0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0, 0, 0, 0, 0, 0],  # x22
[0, 0, 0, 0, 0, 1, 0, 1, 20, 0, 0, 0, 0, 0, 0, 0],  # x23
[0, 0, 0, 0, 1, 0, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0],  # x24
[0, 0, 0, 1, 0, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # x25
[0, 0, 1, 0, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # x26
[0, 1, 0, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # x27
[1, 0, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],  # x28   
[0, 1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20], # x29
[1, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 20, 0], # x30
]

poly_deg = 16
mult_deg = 2 * poly_deg -1


# Add two elements of GF(8), two binary polynomails in GF(8)
def coeff_add(a, b):
    return a ^ b


# multiply two elements of GF(8), two binary polynomials in GF(8)
def coeff_mul(a, b):
    p = 0
    while (b):
        if (b & 1):
            p = p ^ a
        if (a & 0x80):
            a = (a << 1) ^ 0x11b
        else:
            a <<= 1
        b >>= 1

    return p


# polynomial reductions using the irreducible polynomial define at the top
def reduce_poly(mult_poly):
    result = [0] * poly_deg
    # to go through x16 to x30 and replace them
    for j in range(15):
        # create the subpoly for xi, 15< i <31
        sub_poly = [0] * poly_deg
        # get the coeff or xi, 15< i <31
        sub_coeff = mult_poly[j]
        
        if sub_coeff != 0:    
            # since the subpolies are degree 16
            for i in range(poly_deg):
                # 14-j because x30 is at the subpoly[14] but is the mult_poly[0]
                sub_poly[i] = coeff_mul(subpolys[14 - j][i], sub_coeff)
            
            # add up all the subpolies and store in result
            for k in range(poly_deg):
                result[k] = coeff_add(result[k], sub_poly[k])
                
    # add mult_poly result with the result (sum of all the substitutions)
    final_result = [0] * poly_deg
    
    for k in range(poly_deg):
        # k+15, since mult_poly is of degree 31
        final_result[k] = coeff_add(result[k], mult_poly[k+15])

    return final_result


# mulitply two polynomial
def mult_poly(poly1, poly2):
    # initialize multpoly (result)
    multpoly = [0] * mult_deg

    for i in range(poly_deg):
        for j in range(poly_deg):
            # for each mononomial use multiply them using coeff_mult (* in GF(8))
            # and add them using coeff_add (+ in GF(8))
            multpoly[i+j] = coeff_add(multpoly[i+j], coeff_mul(poly1[i] , poly2[j]))
    reducedpoly = reduce_poly(multpoly)
    return reducedpoly


class DCE:
    
    def __init__(self, fw_rb, k, pa, pb, r, m=None):
        self.fw_rb = fw_rb
        self.r = r
        self.k = k
        self.pa = pa
        self.pb = pb
        self.h = None
        if m:
            self.m = m
    
    # return the hex value of a string
    @staticmethod
    def str_2_hex(s_in):
        return "".join("{:02x}".format(ord(c)) for c in s_in)
        
    # turn hex string into array that can be used for polynomial mult
    @staticmethod
    def get_array_repr(k):
        return map(ord, k)
    
    # turn the polynomial array result in to hex string
    @staticmethod
    def get_hex_repr(arr_k):
        return "".join(map(chr, arr_k))
    
    # xor to strings of 16
    @staticmethod
    def xor(m1, m2):
        res = []
        for i in range(len(m1)):
            res.append(chr(ord(m1[i]) ^ ord(m2[i])))
        return "".join(res)
        
    # get the blocks of size 16 of message
    @staticmethod
    def get_blocks(m):
        start = 0
        end = 16
        msg_size = len(m)
        while (start < msg_size):
            yield m[start:end]
            start = end
            end = start + 16
        
    def gen_k0(self, h=None, fw_msg=None):
        sha = SHA.new()

        if h and self.fw_rb == "rb":
            self.h = h

        elif self.fw_rb == "fw" and fw_msg:
            sha.update(fw_msg)
            self.h = sha.digest()[:16]

        else:
            raise Exception

        # k0 = F*(h, k)
        self.k0 = DCE.get_hex_repr(mult_poly(DCE.get_array_repr(self.h),
                                             DCE.get_array_repr(self.k)))

        return self.k0
    
    # generate next block_key and return it, also set current_block_key to this value, enc pb to get yi, SHA(h, pb)
    def get_next_block_key(self):
        sha = SHA.new()
        sha.update(self.current_block_key)
        sha.update(self.pa)
        self.current_block_key = sha.digest()[:16]
        return self.current_block_key
    
    # encrypt the message
    def enc(self, m=None):

        if m:
            self.m = m
        
        self.current_block_key = self.k0        
        self.cipher_text = ""
        
        first = True

        for block in DCE.get_blocks(self.m):
            sha = SHA.new()
            sha.update(self.current_block_key)
            sha.update(self.pb)
            k = sha.digest()[:16]

            if first:
                print "First block key: " + k.encode('hex')
                first = False

            # this is ci
            c = DCE.xor(block, k)
            self.cipher_text += c
            # set the new block key
            self.get_next_block_key()
            
        return self.cipher_text

    # decrypt the message
    def dec(self, cipher=None):
        if cipher:
            self.cipher_text = cipher
        
        self.current_block_key = self.k0

        self.plain_text = ""
        
        for block in DCE.get_blocks(self.cipher_text):

            sha = SHA.new()
            sha.update(self.current_block_key)
            sha.update(self.pb)
            k = sha.digest()[:16]

            # this is pi
            p = DCE.xor(block, k)
            self.plain_text += p
            # set the new block key
            self.get_next_block_key()
            
        return self.plain_text
