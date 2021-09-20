from wrapper import BpGroup, G1Elem, G2Elem
from hashlib  import sha256
from binascii import hexlify, unhexlify
#from petlib.bn import Bn # only used to hash challange
import numpy as np

from bn128 import FQ


# ==================================================
# setup
# ==================================================

def setup():
	G = BpGroup()
	g1, g2 = G.gen1(), G.gen2()
	e, o = G.pair, G.order()
	# print((G, o, g1, g2, e))
	return (G, o, g1, g2, e)

#===============================
# CAKeygen
#============================
def CAKeygen(params,m=4,n=2):
	""" generate a key pair of CA , m denoted attributes"""
	(G, o, g1, g2, e) = params
	# n = 2
	list_y = []
	for i in range(m):
		list_y.append(o.random())
	x = o.random()
	list_y = tuple(list_y)
	print(x,list_y)
	# print(x,y)
	sk = (x, list_y)
	vk = [g2]
	vk.append(x*g2)

	for i in range(len(list_y)):
		vk.append(list_y[i]*g2)
	return (sk, vk, m)

def TraceKeygen(params):
	""" generate a key pair of CA , m denoted attributes"""
	(G, o, g1, g2, e) = params
	z = o.random()
	trace = z
	Z = z*g2
	return (trace, Z)

# ===================================================
# inversion
# ===================================================
def inv(a, n):  ### EDITED ###
	""" extended euclidean algorithm """
	if a == 0:
		return 0
	lm, hm = 1, 0
	low, high = a % n, n
	while low > 1:
		r = high//low
		nm, new = hm-lm*r, high-low*r
		lm, low, hm, high = nm, new, lm, low
	return lm % n
# ====================================================
# generate to_challenge
# ====================================================
def to_challenge(elements):
    """ generates a Bn challenge by hashing a number of EC points """
    Cstring = b",".join([hexlify(x.export()) for x in elements])
    Chash =  sha256(Cstring).digest()
    #return Bn.from_binary(Chash)
    return int.from_bytes(Chash, 'big') ### EDITED ###

# ===================================================
# issue
# ===================================================
    """signature on hidden message"""
#===================
#request
#===================
def request(params, Z, m, attributes, ID) :
	""" build elements for blind sign """
	(G, o, g1, g2, e) = params
	#list_Y2 = []
	#for i in range(m):
	#	list_Y2.append(vk[i + 2])
	hid=int.from_bytes(sha256(ID.encode("utf-8")).digest(),'big')%o
	h=hid*g1
	list_alpha = []
	for i in range(len(attributes)):
		list_alpha.append(int.from_bytes(sha256(attributes[i].encode("utf-8")).digest(),'big')%o)
	# alpha = o.random()
	list_si = []
	for i in range(len(attributes)):
		list_si.append(o.random())
	#si = o.random()
	S1 = []
	for i in range(len(attributes)):
		S1.append(list_si[i] * g2)
	#S1 = si*g2
	S2 = []
	for i in range(len(attributes)):
		S2.append(list_alpha[i] * g2 + list_si[i] * Z)
	#S2 = alpha * g2 + si * Z
	hi = []
	for i in range(len(attributes)):
		hi.append(list_alpha[i] * h)
	# hi = alpha * h
	# proof of correctness
	proof = prove_commitment(params, Z, S1, S2, hi, list_si, list_alpha, h, m)
	return (S1, S2, hi, proof, list_si, list_alpha, h)

def prove_commitment(params, Z, S1, S2, hi, list_si, list_alpha, h, m):
	""" prove correct commitment """
	(G, o, g1, g2, e) = params
	# u1 [], u2 []
	# 生成随机数
	u1, u2 = [], []
	for i in range(m):
	    u1.append(o.random())
	for i in range(m):
		u2.append(o.random())
	# create the proof
	# compute the witnesses commitments
	#a,b,d
	a, b, d = [], [], []
	for i in range(m):
		a.append(u1[i] * g2)
		b.append(u2[i] * g2 + u1[i] * Z)
		#u2 * g2 + u1 * Z
		c.append(u2[i] * h)
	# create the challenge
	#c = to_challenge([g1, g2,(o.random())*g2, (o.random())*g2,Aw]+[g1])
	c = to_challenge([g1, g2, S1, S2, hi, a, b, d]+[g1])
	# create responses
	s1, s2 = [], []
	for i in range(m):
		s1.append((u1[i] + c * list_si)%o)
		s2.append((u2[i] + c * list_alpha)%o)

	return (c, s1, s2, a, b, d)
#=================================
#blind
#=================================
def blind(params, sk, S1, S2, hi, Z, proof, h):
	""" blindly sign a message """
	(G, o, g1, g2, e) = params
	(x, list_y) = sk
	#list_Y2 = []
	#m = len(list_y)
	#for i in range(m):
	#	list_Y2.append(vk[i + 2])
	# verify proof of correctness
	# if not verify_commitment(params, vk, S1, S2, hi, proof):
	# 	raise Exception('Parameters format error.')
	# issue PS signature
	A = h
	B = x * h
	for i in range(m):
		B= B + list_y[i] * hi[i]
	sigg =(A, B)
	# ps sig
	return (sigg)

def verify_commitment(params, Z, S1, S2, hi, proof, h, m):
	""" verify correct commitment """
	(G, o, g1, g2, e) = params
	list_Y2 = []
	for i in range(m):
		list_Y2.append(vk[i+2])
	(c, s1, s2, a, b, d) = proof
	# re-compute witnesses commitments
	verify1, verify2, verify3 = [], [], []
	#leftverify
	for i in range(len(s1)):
		verify1.append(s1[i] * g2)
	for i in range(len(s1)):
	    verify2.append(s2[i] * h)
	for i in range(len(s1)):
		verify3.append(s2[i] * g2 + s1[i] * Z)

#	for i in range(1,len(list_s)):
#		verify2 = verify2 + list_s[i] * list_Y2[i]
	for i in range(m):
		if ((verify1[i] == a + c * S1[i]) and (verify2[i] == d + c * hi[i]) and (verify3[i] == b + c * S2[i])):
	#assert (verify1[1] == a + c * S1[1])
		# compute the challenge prime
			c == to_challenge([g1, g2, S1, S2, hi, a, b, d] + [g1])
		#return ()
	#return c
	return c
			#return False
# ======================================================
# PS signatures
# ======================================================
# def sign(params, sk, m):
# 	""" sign a clear message """
# 	(G, o, g1, hs, g2, e) = params
# 	(x, y) = sk
# 	uu = o.random()
# 	A = uu*g1
# 	B = uu*((x+y*m)*g1)
# 	sig = (A, B)
# 	return (sig)
# =======================================================
# Randomize
# =======================================================
def randomize(params, sigg):
	""" randomize signature  """
	(G, o, g1, g2, e) = params
	sig1 , sig2 = sigg
	t = o.random()
	return ( t*sig1 , t*sig2 )

# ======================================================
#unblind
#=====================
def unblind(params, vk, sigg, list_alpha, m):
	""" unblind the credential """
	(G, o, g1, g2, e) = params
	list_Y2 = []
	X = vk[1]
	for i in range(m):
		list_Y2.append(vk[i + 2])
	#verify e(sig2, g2) = e(h, X + alpha * Y)
	(sig1, sig2) = sigg
	#e(sigma, g2)
	esig2 = e(sig2, g2)
	#e(h,XY)
	esig1 =X
	for i in range(m):
	    esig1 = esig1 + list_alpha[i] * list_Y2[i]
	hesig1 = e(sig1, esig1)
	if (esig2 == hesig1):
	    sig = (sig1, sig2)
	    C= (list_alpha, sig)
	    return C
    #else:
	#	return False
# ======================================================
# Showing
# ======================================================

#without the revocation element
def show_credential(params, vk, C, m):
	(G, o, g1, g2, e) = params
	list_Y2 = []
	for i in range(m):
		list_Y2.append(vk[i + 2])
	(list_alpha, sig) = C
	#randomize ps signatures
	D = randomize(params, sig)
	(c, d) = D
	#commitment
	# hash(c) =f[]
	f, Fl = [], []
	for i in range(m):
		f.append(to_challenge([c, list_Y2[i]] + [g1]))
	for i in range(m):
		Fl.append(f[i] * g1)
	Fi = list_alpha[0] * Fl[0]
	for i in range(1, m):
	    Fi = Fi + list_alpha[i]* Fl[i]
	# generate proof
	proof = prove_show_credential(params, vk, c, d, Fi, Fl, list_alpha)
	return (c, d, Fi, proof)

#================================
#zero-knowledge proof
#================================
def prove_show_credential(params, vk, c, d, Fi, Fl, list_alpha):
	""" prove correct commitment """
	(G, o, g1, g2, e) = params
	m = len(list_alpha)
	list_Y2 = []
	for i in range(m):
		list_Y2.append(vk[i + 2])
	# compute f[]
	#f, Fl = [], []
	#for i in range(m):
	#	f.append(to_challenge([c, list_Y2[i]] + [g1]))
 	#for i in range(m):
#		Fl.append(f[i] * g1)
	# random generate
	u1 = []
	for i in range(m):
		u1.append(o.random())
	a, b = [], []
	for i in range(m):
		a.append(u1[i] * Fl[i])
	al = a[0]
	for i in range(1, m):
		al = al + a[i]
	for i in range(m):
		b.append(u1[i] * list_Y2[i])
	dl = b[0]
	for i in range(1, m):
		dl = dl + b[i]
	bl = e(c, dl)
	# create challenge
	c1 = to_challenge([g1, g2, al, bl]+[g1])
	s1 = []
	for i in range(m):
		s1.append((u1[i] + c1 * list_alpha[i])%o)
	return (c1, s1, al, bl, Fl)
# =======================================================
# Verify
# =======================================================

def verify_credential(params, vk, c, d, Fi, proof, m):
    #""" verify a credential on a hidden message """
	(G, o, g1, g2, e) = params
	list_Y2 = []
	X = vk[1]
	for i in range(m):
		list_Y2.append(vk[i + 2])
	(c1, s1, al, bl, Fl) = proof
	#check si*f == a + cl* Fi
	#a + c1 *Fi =verify1
	verify1 = al + c1 * Fi
	#s1 * fi= verify2
	verify2 = s1[0] * Fl[0]
	for i in range(1, m):
		verify2 = verify2 + s1[i] * Fl[i]
    # e(s1*c, Y)
	verify3 = []
	for i in range(m):
		verify3.append(s1[i] * list_Y2[i])
	dl = verify3[0]
	for i in range(1, m):
		dl = dl + verify3[i]
	verify4 = e(c, dl)
	#b*e(d,g2)/e(c,x)
	ci = inv(c1, o)# inversion c1
	verify5 = e(d, c1*g2) * e(c, ci*X)
	verify6 = bl * verify5
	if (verify1 == verify2 and verify4 == verify5):
	   return (c1 == to_challenge([g1, g2, al, bl]+[g1]))
	else:
		return False
 ##=========================================
 #Trace
 #==========================================
def trace(params, vk, tk, c, d, Fi, proof, m, S1, S2):
	"""trace user credential with trace key"""
	(G, o, g1, g2, e) = params
	list_Y2 = []
	X = vk[1]
	for i in range(m):
		list_Y2.append(vk[i + 2])
	z = tk
	f, F1 = [], []
	for i in range(m):
		f.append(to_challenge([c, list_Y2[i]] + [g1]))
	for i in range(m):
		F1.append(f[i] * g1)
	#alpha* g2
	value = []
	for i in range(m):
		value.append(S2[i] - z * S1[i])
	#e(alpha*f,g2)
	verify1 = e(Fi, g2)
	#e(f,alpha*g2)
	verify2 = e(F1[0], value[0])
	for i in range(1, m):
		verify2 = verify2 * e(F1[i], value[i])
	if (verify1 == verify2):
		return (value)
	else:
		return False

# =======================================================
# revocation
# =======================================================
def revaction(params, value, c, d, Fi, m ):
    #CA pubish k3 and s2 to blockchain to revoke the user1
	(G, o, g1, g2, e) = params
	list_Y2,f, Fl = [], [], []
	for i in range(m):
		list_Y2.append(vk[i + 2])
	for i in range(m):
		f.append(to_challenge([c, list_Y2[i]] + [g1]))
	for i in range(m):
		Fl.append(f[i] * g1)
	#e(alpha*f,g2)
	verify1 = e(Fi, g2)
	#e(f,alpha*g2)
	verify2 = e(Fl[0], value[0])
	for i in range(1, m):
		verify2 = verify2 * e(Fl[i], value[i])
	assert (verify1 == verify2)
