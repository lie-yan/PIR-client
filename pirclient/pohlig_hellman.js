// object navigator created for running under Rhino engine
var navigator = new Object();
navigator.appName = "rhino";

// load libs
load("/Users/robin/Dropbox/KAUST Course/Computer Security/pirclient/jslib/jsbn.js");
load("/Users/robin/Dropbox/KAUST Course/Computer Security/pirclient/jslib/jsbn2.js");
load("/Users/robin/Dropbox/KAUST Course/Computer Security/pirclient/jslib/prng4.js");
load("/Users/robin/Dropbox/KAUST Course/Computer Security/pirclient/jslib/rng.js");

var rng = new SecureRandom();
var BigIntegerTWO   = new BigInteger("2", 10);
var BigIntegerTHREE = new BigInteger("3", 10);
/**
 * 
 * @param alpha
 * @param beta
 * @param order
 * @param modulus
 * @param a0 default 0; if it fails, choose a random in [1..n-1]
 * @param b0 default 0; if it fails, choose a random in [1..n-1]
 * @returns {BigInteger}
 */
function phPollard_rho(alpha, beta, order, modulus, a0, b0) {
	var x = alpha.modPow(a0, modulus).multiply(beta.modPow(b0, modulus)).mod(modulus); 
	var a = a0;
	var b = b0;
	var X = x.clone();
	var A = a.clone();
	var B = b.clone();
	
	while (true) {
		var category = getCategory(x, modulus);
		x = phNextX(x, alpha, beta, modulus, category);
		a = phNextA(a, alpha, beta, order, category);
		b = phNextB(b, alpha, beta, order, category);
		category = getCategory(X, modulus);
		X = phNextX(X, alpha, beta, modulus, category);
		A = phNextA(A, alpha, beta, order, category);
		B = phNextB(B, alpha, beta, order, category);
		category = getCategory(X, modulus);
		X = phNextX(X, alpha, beta, modulus, category);
		A = phNextA(A, alpha, beta, order, category);
		B = phNextB(B, alpha, beta, order, category);
		/*
		print(x.toString() + " " + a.toString() + " " + b.toString() 
				+ " " + X.toString() + " " + A.toString() + " " + B.toString());
		 */			
		if (x.equals(X)) {
			var r = b.subtract(B).mod(order);
			if (r.equals(BigInteger.ZERO)) {
				return new BigInteger("-1", 10); // failure
			} else {
				var deltaA = A.subtract(a);
				var invR = r.modInverse(order);
				return invR.multiply(deltaA).mod(order);
			}
		}
	}
}


function getCategory(x, modulus) {
	var t1, t2;
	var THREE = new BigInteger("3", 10);
	t1 = modulus.divide(THREE);
	t2 = modulus.subtract(t1);
	if (x.compareTo(BigInteger.ZERO) > 0 && x.compareTo(t1) <= 0) {
		return 0;
	} else if (x.compareTo(t2) < 0) {
		return 1;
	} else {
		return 2;
	}
}

function phDiscreteLog(alpha, beta, order, modulus) {
	var a0 = BigInteger.ZERO.clone();
	var b0 = BigInteger.ZERO.clone();

	var falseAns = new BigInteger("-1", 10);
	do {
		var ans = phPollard_rho(alpha, beta, order, modulus, a0, b0);
		/*
		print(a0.toString());
		print(b0.toString());
		print(ans.toString());
		*/
		a0  = new BigInteger(order.bitLength(), rng);
		a0  = a0.mod(order);
		if (a0.equals(BigInteger.ZERO)) {
			a0 = a0.add(BigInteger.ONE);
		}
		b0  = new BigInteger(order.bitLength(), rng);
		b0  = b0.mod(order);
		if (b0.equals(BigInteger.ZERO)) {
			b0 = b0.add(BigInteger.ONE);
		}
	}while (ans.equals(falseAns));
	return ans;
}

function phNextX(xi, alpha, beta, modulus, category) {
	// category = 1, 2, or 0
	if (category == 2) {
		return xi.multiply(beta).mod(modulus);
	} else if (category == 1) {
		return xi.modPow(BigIntegerTWO, modulus);
	} else {
		return xi.multiply(alpha).mod(modulus);
	}
}

function phNextA(a, alpha, beta, order, category) {
	// category = 1, 2, or 0
	if (category == 2) {
		return a;
	} else if (category == 1) {
		return a.add(a).mod(order);
	} else {
		return a.add(BigInteger.ONE).mod(order);
	}	
}

function phNextB(b, alpha, beta, order, category) {
	// category = 1, 2, or 0
	if (category == 2) {
		return b.add(BigInteger.ONE).mod(order);
	} else if (category==1) {
		return b.add(b).mod(order);
	} else {
		return b;
	}
}

/**
 * 
 * @param alpha
 * @param beta
 * @param order
 * @param modulus
 * @param base  a prime such that base^exp = order
 * @param exp   base^exp = order
 */
function phSpecializedPholigHellman(alpha, beta, order, modulus, base, exp) {
	var q = base;
	var e = exp;
	//print("alpha " + alpha.toString());
	//print("order of alpha " + order.toString());
	//print("base " + base.toString());
	var alphaBar = alpha.modPow(order.divide(q), modulus);
	var orderBar = q;

	//print("alpha bar " + alphaBar.toString());
	//print("order bar " + orderBar.toString());
	
	// compute ell_0
	var gamma = BigInteger.ONE;
	var invGamma = gamma.modInverse(modulus);
	
	var t1 = order.divide(q);
	var betaBar = beta.multiply(invGamma).modPow(t1, modulus);
	
	var ell = phDiscreteLog(alphaBar, betaBar, orderBar, modulus);
	var ans = ell.clone();
	
	// print(ell.toString());
	
	for (j = BigInteger.ONE; j.compareTo(e) < 0; j = j.add(BigInteger.ONE)) {
		var t2 = ell.multiply(q.modPow(j.subtract(BigInteger.ONE), modulus)).mod(order);
		gamma = gamma.multiply(alpha.modPow(t2, modulus)).mod(modulus);
		invGamma = gamma.modInverse(modulus);
		t1 = t1.divide(q);
		betaBar = beta.multiply(invGamma).modPow(t1, modulus);
		
		ell = phDiscreteLog(alphaBar, betaBar, orderBar, modulus);
		// print(orderBar.toString());
		// print(betaBar.toString());
		// print(ell.toString());
		ans = ans.add(ell.multiply(q.modPow(j, modulus)));
	}

	return ans;
}

// test Pollard-rho algorithm
/*
var alpha = BigIntegerTWO.clone();
var beta = new BigInteger("228", 10);
var modulus = new BigInteger("383", 10);
var order  = new BigInteger("191", 10);

var ans = phDiscreteLog(alpha, beta, order, modulus);
print(ans.toString());
*/

var base = new BigInteger("11", 10);
var exp = new BigInteger("3", 10);
var	m=new BigInteger("4331953844689", 10);
var	h=new BigInteger("1327508257514", 10);
var orderH = new BigInteger("1331", 10);
var q = new BigInteger("1627328902", 10);
var ge = new BigInteger("3492401415657", 10);
var beta = ge.modPow(q, m);
print("beta " + beta.toString());
var ans = phSpecializedPholigHellman(h, beta, orderH, m, base, exp);
print("ans " + ans.toString());
