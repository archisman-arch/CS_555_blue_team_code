def sum( arg1, arg2, arg3, p ):
   # Add both the parameters and return them."
   total = (arg1 + arg2 + arg3) % p
   #print ("Inside the function sum : ", total)
   return total;

# Now you can call sum function
#total = sum( 10, 20, 30 );

def mul( arg1, arg2, arg3):
   # Add both the parameters and return them."
   mul = arg1 * arg2 % arg3
   #print ("Inside the function mul : ", mul)
   return mul;

# Now you can call mul function
#total = mul( 10, 20, 30 );

def secret_key_rec (x1,x2,x3,p):
    # secret key reconstruction modulo p
    x_local = mul(x1, x2, p);
    x = mul(x_local, x3, p)
    secret = x
    # for i in range(1,x+1):
    #     secret = mul(secret, g, p)
    #     #print ("Inside the function : ", secret, g, p)
    #print ("Inside the function : ", secret, g, p)
    #print ("Inside the function : ", secret)
    return secret;

def g_x_calc (g,x,p):
    # secret key reconstruction modulo p
    g_x = 1
    for i in range(1,x+1):
        g_x = mul(secret, g, p)
        #print ("Inside the function : ", secret, g, p)
    #print ("Inside the function : ", secret, g, p)
    #print ("Inside the function : ", secret)
    return g_x;

# Now you can call key reconstruction function
secret = secret_key_rec( 1, 2, 1, 20 );  

def decryption (cipher, secret, p):
    inv_secret = 1;
    for i in range(1,p-2+1):
        inv_secret = mul(inv_secret, secret, p)
        #print ("Inside the function inverse secret: ", inv_secret)
    msg = mul(inv_secret, cipher, p)
    return msg;
# Now you can call key decryption function
msg = decryption( 3, 5, 7 );  


def inverse ( x, p):
    inv_x = 1;
    for i in range(1,p-2+1):
        inv_x = mul(inv_x, x, p)
        #print ("Inside the function inverse secret: ", inv_x)
    return inv_x;
# Now you can call key decryption function
inv_x = inverse( 5, 7 );  

def shamir_sharing_degree2 (alpha, s, p):
    #polynomial = s+3x+5x^2; should be random for perfect secrecy
    a_2 = 5
    a_1 = 9
    alpha_2 = mul(alpha, alpha, p);
    term2 = mul(alpha_2, a_2,p);
    #term2= mul(term2, 5, p)
    term1 = mul(alpha, a_1,p);
    #term1 = mul (term1, 3, p) 
    sharing = sum(s, term1, term2, p)
    return sharing;
# Now you can call shamir sharing function -- to check later

#I avoided to write it logically to make 1:1 representation with MPC circuit level architecture taught in class
#note that only calculating 0 will be enough
#reconstruct will be given to the C
def shamir_sharing_reconstruction_degree_2 (s1, s2, s3, alpha1, alpha2, alpha3,p): 
    l1 = mul(alpha2,alpha3,p);
    l1_div = mul(alpha1-alpha2, alpha1-alpha3,p)
    l1_mul = inverse (l1_div, p)
    l1 = mul(l1, l1_mul, p) 
    l2 = mul(alpha1,alpha3,p);
    l2_div = mul(alpha2-alpha1, alpha2-alpha3,p)
    l2_mul = inverse (l2_div, p)
    l2 = mul(l2, l2_mul, p) 
    l3 = mul(alpha1,alpha2,p);
    l3_div = mul(alpha3-alpha1, alpha3-alpha2,p)
    l3_mul = inverse (l3_div, p)
    l3 = mul(l3, l3_mul, p) 
    s = (s1 * l1 + s2 *l2 + s3* l3 ) % p
    return s

def trusted_party_circuit(c1, c2, c3, gx1, gx2, gx3,p, id ):
    #Assumption: trusted party magically generates the calculation points , it should be generated randomly. Here user can chage 1st 23 lines of teh function, they should be less than p
    alpha1 = 1;
    alpha2 = 2;
    alpha3 = 3;
    gx = gx1 * gx2 * gx3 % p;
    m1 = decryption (c1, gx, p) 
    m2 = decryption (c2, gx, p) 
    m3 = decryption (c3, gx, p) 
    m1m2 = mul (m1, m2, p)
    s = sum(m1m2, m3, 0, p)
    print("secret:", s)
    s1 = shamir_sharing_degree2 (alpha1, s, p)
    s2 = shamir_sharing_degree2 (alpha2, s, p)
    s3 = shamir_sharing_degree2 (alpha3, s, p)
    if id == 'P1':
        return alpha1, s1
    elif id == 'P2':
        return alpha2, s2
    elif id == 'P3':
        return alpha3, s3
    else:
        return none 
    #return alpha1, alpha2,alpha3, s1, s2, s3

def conditional_exchange(party_id, ALGO, alpha1, alpha2, alpha3, s1, s2, s3):
    if (ALGO > 3333.33) and (party_id == 'P1'):
        return alpha1, s1
    elif (ALGO > 3333.33) and (party_id == 'P2'):
        return alpha2, s2
    elif (ALGO > 3333.33) and (party_id == 'P3'):
        return alpha3, s3 

    




x1 = 1;
g = 3
y = 5

p = 13
#g = g ** y %p
gx1 = g ** x1 % p;
c1 = 5; 
#P2 output to trusted party
c2 = 1;
x2 = 6;

gx2 = g ** x2 % p;
#P3 output to trusted party
c3 = 2; 
x3 = 3;

gx3 = g ** x3 % p;
#alpha1,alpha2,alpha3,s1,s2,s3 = trusted_party_circuit(c1, c2, c3, gx1, gx2, gx3,p)
alpha1,s1 = trusted_party_circuit(c1, c2, c3, gx1, gx2, gx3,p,'P1')
alpha2,s2 = trusted_party_circuit(c1, c2, c3, gx1, gx2, gx3,p,'P2')
alpha3,s3 = trusted_party_circuit(c1, c2, c3, gx1, gx2, gx3,p,'P3')
#Assumption returned to parties and adversary/client does not have any visibility over it
print("Sharing of P1:",s1)
print("Sharing of P2:",s2)
print("Sharing of P3:",s3)

#client code
#retrieval of shares
alpha1_c,s1_c=conditional_exchange('P1', 3334 , alpha1, alpha2, alpha3, s1, s2, s3)
alpha2_c,s2_c=conditional_exchange('P2', 3334 , alpha1, alpha2, alpha3, s1, s2, s3)
alpha3_c,s3_c=conditional_exchange('P3', 3334 , alpha1, alpha2, alpha3, s1, s2, s3)
#reconstruction by client
s = shamir_sharing_reconstruction_degree_2 (s1_c, s2_c, s3_c, alpha1_c, alpha2_c, alpha3_c,p)
print("Reconstructed secret:",s)

