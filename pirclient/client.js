
// object navigator created for running under Rhino engine
var navigator = new Object();
navigator.appName = "rhino";

// load libs
load("/Users/robin/Dropbox/KAUST Course/Computer Security/pirclient/jslib/jsbn.js");
load("/Users/robin/Dropbox/KAUST Course/Computer Security/pirclient/jslib/jsbn2.js");
load("/Users/robin/Dropbox/KAUST Course/Computer Security/pirclient/jslib/prng4.js");
load("/Users/robin/Dropbox/KAUST Course/Computer Security/pirclient/jslib/rng.js");


// Gloabals
// random number generator
var rng = new SecureRandom();
// to what degree should the number be tested for primality
var PRIME_TEST_DEG = 10;
// constants
var BigIntegerTWO   = new BigInteger("2", 10);
var BigIntegerTHREE = new BigInteger("3", 10);

/**
 * generate a random prime $q_{1}$ such that $p_{1}=2*q_{1}*\pi_{i}+1$ where $q_{1}$ is a prime,
 * return $p_{1}$ and $q_{1}$
 * @param pi $\pi_{i}$
 * @param len length of $q_{1}$
 * @returns {_p1, _q1}
 */
function grGetP1(pi, len) {
	var p1, q1;

	do {
		// generate a prime
		q1 = new BigInteger(len, PRIME_TEST_DEG, rng);	
		
		//print(q1.toString());
		// compute p1 = 2*pi*q1 + 1
		p1 = q1.multiply(pi.value).multiply(new BigInteger("2",10)).add(BigInteger.ONE);
	} while(p1.isProbablePrime(PRIME_TEST_DEG) == false); // iterate until p1 is a prime
	return {_p1:p1, _q1:q1};
}

/**
 * generate a random prime $q_{2}$ such that $p_{2}=2*q_{2}*d+1$ is a prime, where $d$ is a random number,
 * return $p_{2}$, $q_{2}$, and $d$.
 * @param pi $\pi_{i}$
 * @param len length of $q_{2}$
 * @returns {_p2, _q2, _d}
 */
function grGetP2(pi, len) {
	var q2, d;
	var p2;
	do {
		// generate a prime
		q2 = new BigInteger(len, PRIME_TEST_DEG, rng);
		// generate a random
		d  = new BigInteger(pi.value.bitLength(), PRIME_TEST_DEG, rng);
		// compute p2 = 2*d*q2 + 1
		p2 = q2.multiply(d).multiply(new BigInteger("2",10)).add(BigInteger.ONE);
	} while(p2.isProbablePrime(PRIME_TEST_DEG)==false); // iterate until p2 is a prime
	return {_p2:p2, _q2:q2, _d:d};
}

/**
 * generate a random prime $q_{1}$ such that $p_{1}=2*q_{1}*\pi_{i}+1$ is a prime,
 * generate a random prime $q_{2}$ such that $p_{2}=2*q_{2}*d+1$ is a prime, where $d$ is a random number,
 * return $p_{1}$, $p_{2}$, $q_{1}$, $q_{2}$, and $d$.
 * @param pi $\pi_{i}$
 * @param len length of $q_{1}$ and $q_{2}$, in bits
 * @returns {$p_{1}$, $p_{2}$, $q_{1}$, $q_{2}$, and $d$}
 */
function grGetPrimes(pi, len) {
	var r1 = grGetP1(pi, len);
	var r2 = grGetP2(pi, len);
	
	return {_p1:r1._p1, _p2:r2._p2, _q1:r1._q1, _q2:r2._q2, _d:r2._d};
}

/**
 * select a number $g$ in random, such that $gcd(m,g)=1$, 
 * and the order of cyclic group <g> is a multiple of $\pi_{i}$
 * @param m  the modulus
 * @param pi $\pi_i$
 * @param params {_p1, _p2, _q1, _q2, _d}
 * @returns {_g, _order} where _order is the order of the cyclic group <_g>
 */
function grSelectG(m, pi, params) {
	var g, order;
	
	do {
		// iterate until gcd(g, m)=1
		do {
			g = new BigInteger(m.bitLength(), rng);
			g = g.mod(m);
		} while(g.remainder(params._p1).equals(BigInteger.ZERO)
				|| g.remainder(params._p2).equals(BigInteger.ZERO)); 
		// print("g=" + g.toString());
		// print("d=" + params._d.toString());
		// compute order
		if (grIsCorrectOrder(g, m, pi.value, params))
		{
			var prod = pi.value.multiply(params._q1).multiply(params._q2).multiply(params._d).multiply(new BigInteger("4"));
			var bases = new Array(new BigInteger("2",10), 
					params._q1, params._q2, params._d, pi.base);
			var exps  = new Array(new BigInteger("2", 10), 
					BigInteger.ONE, BigInteger.ONE, BigInteger.ONE, pi.exp);
			order = grCountOrder(g, m, bases, exps, prod);
			// print("order=" + order.toString());
		}  else {
			order = BigInteger.ONE;
		}
	} while(order.remainder(pi.value).equals(BigInteger.ZERO)==false);
	return {_g:g, _order:order, _d:params._d};
}

function grIsCorrectOrder(g, m, pi, params) {
	var prod = params._q1.multiply(params._q2)
			.multiply(params._d).multiply(new BigInteger("4", 10));
	while (prod.mod(pi).equals(BigInteger.ZERO)) {
		prod = prod.divide(pi);
	}
	if (g.modPow(prod, m).equals(BigInteger.ONE)) {
		return false;
	} else {
		return true;
	}
}

/**
 * compute the order of the cyclic group <g>.
 * To compute this, we need know the prime factorization of a multiple of the order of <g>.
 * We choose the order of the group {g | gcd(g,m)=1}, whose factorization is bases[1]^exps[1] ... bases[i]^exps[i]
 * @param g cyclic group generator 
 * @param m modulus 
 * @param bases 
 * @param exps
 * @param prod the order of the group {g | gcd(g,m)=1}
 * @returns the order of <g>
 */
function grCountOrder(g, m, bases, exps, prod) {
	var t = prod;
	var a1;
	for (x in bases) {
		t = t.divide(bases[x].pow(exps[x]));
		a1 = g.modPow(t, m);
		while (a1.equals(BigInteger.ONE) == false) {
			a1 = a1.modPow(bases[x], m);
			t = t.multiply(bases[x]);
		}
	}
	return t;
}

/**
 * Compute the discrete logarithm of beta to base alpha with Pollard rho algorithm
 * 
 * @param alpha 	the base
 * @param beta  	the power
 * @param order 	the order of the cyclic group <alpha>, should be prime
 * @param modulus 	the modulus used in multiplication
 * @param a0 	default 0; if it fails, choose a random in [1..n-1]
 * @param b0 	default 0; if it fails, choose a random in [1..n-1]
 * @returns the discrete logarithm of beta to base alpha if success, or -1 if failure
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

/**
 * function used in specialized Pohlig-Hellman algorithm
 */
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
/**
 * function used in specialized Pohlig-Hellman algorithm
 */
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
/**
 * function used in specialized Pohlig-Hellman algorithm
 */
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

function sqrt(x) {
	var TWO = new BigInteger("2", 10);
	var square = new BigInteger("1", 10);
	var delta  = new BigInteger("3", 10);
	
	while (square.compareTo(x) <= 0) {
		square = square.add(delta);
		delta = delta.add(TWO);
	}
	return delta.divide(TWO).subtract(BigInteger.ONE);
}

function ceilSqrt(x) {
	var root = sqrt(x);
	if (root.square().equals(x)) {
		return root;
	} else {
		return root.add(BigInteger.ONE);
	}
}

function pairCmp(a, b) {
	return a[1].compareTo(b[1]);
}

function bSearch(x, list) {
	var left = 0; 
	var right = list.length - 1;
	while (left <= right) {
		var mid = Math.floor((left+right)/2);
		if (list[mid][1].equals(x)) {
			return list[mid][0];
		} else if (list[mid][1].compareTo(x) < 0){
			left = mid+1;
		} else {
			right = mid-1;
		}
	}
	return null;
}

// http://en.wikipedia.org/wiki/Baby-step_giant-step
function shank(alpha, beta, order, modulus) {
	var m = ceilSqrt(order);

	var list = new Array();
	for (var i = BigInteger.ZERO; i.compareTo(m) < 0; i = i.add(BigInteger.ONE)) {
		list.push([i, alpha.modPow(i, modulus)]);
	}
	list.sort(pairCmp);
	
	var inv_malpha = alpha.modPow(m, modulus).modInverse(modulus);
	var gamma = beta;
	
	for (var i = 0; i < m.intValue(); i++) {
		var j = bSearch(gamma, list);
		if (j != null) {
			var index = new BigInteger(i.toString(), 10);
			return index.multiply(m).add(j);
		} else {
			gamma = gamma.multiply(inv_malpha).mod(modulus);
		}
	}
}

/**
 * Compute the discrete logarithm of beta to base alpha using Pollard rho algorithm
 * @param alpha		the base
 * @param beta 		the power
 * @param order		the order of the cyclic group <alpha>
 * @param modulus 	the modulus used in multiplication
 * @returns the logarithm of beta to base alpha
 */
function phDiscreteLog(alpha, beta, order, modulus) {

	/*
	var a0 = BigInteger.ONE.clone();
	var b0 = BigInteger.ZERO.clone();

	var falseAns = new BigInteger("-1", 10);
	do {
		var ans = phPollard_rho(alpha, beta, order, modulus, a0, b0);
		
		 print(a0.toString());
		 print(b0.toString());
		 print(ans.toString());
		
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
	*/
	return shank(alpha, beta, order, modulus);
}


/**
 * Compute the discrete logarithm of beta to base alpha using Pohlig-Hellman algorithm
 * As the input of our input is special, we simplified some steps.
 * @param alpha 	the base
 * @param beta		the power
 * @param order		the order of the cyclic group <alpha>
 * @param modulus	the modulus used in multiplication
 * @param base  	a prime such that base^exp = order
 * @param exp   	base^exp = order
 */
function phSpecializedPholigHellman(alpha, beta, order, modulus, base, exp) {
	var q = base;
	var e = exp;
	print("alpha " + alpha.toString());
	print("order of alpha " + order.toString());
	print("base " + base.toString());
	var alphaBar = alpha.modPow(order.divide(q), modulus);
	print("alpha bar " + alphaBar.toString());
	var orderBar = q;
	
	// compute ell_0
	var gamma = BigInteger.ONE;
	var invGamma = gamma.modInverse(modulus);
	
	var t1 = order.divide(q);
	var betaBar = beta.multiply(invGamma).modPow(t1, modulus);
	
	print("beta bar=" + betaBar.toString());
	
	var ell = phDiscreteLog(alphaBar, betaBar, orderBar, modulus);
	var ans = ell.clone();
	
	print("ell=" + ell.toString());
	var j;
	for (j = BigInteger.ONE; j.compareTo(e) < 0; j = j.add(BigInteger.ONE)) {
		var t2 = ell.multiply(q.modPow(j.subtract(BigInteger.ONE), modulus)).mod(order);
		gamma = gamma.multiply(alpha.modPow(t2, modulus)).mod(modulus);
		invGamma = gamma.modInverse(modulus);
		t1 = t1.divide(q);
		betaBar = beta.multiply(invGamma).modPow(t1, modulus);
		
		ell = phDiscreteLog(alphaBar, betaBar, orderBar, modulus);
		ans = ans.add(ell.multiply(q.modPow(j, modulus)));
	}

	return ans;
}

/**
 * constructor of the class pClient
 * @returns {pClient}
 */
function pClient() {
	this.m = null;
	this.g = null;
	this.q = null;
	this.pi = null;
	
	this.generateQuery = function(pi, len) {
		this.pi = pi;
		var ret = grGetPrimes(pi, len);
		var p1 = ret._p1;
		var p2 = ret._p2;
		this.m = p1.multiply(p2);
		
		var ret2 = grSelectG(this.m, pi, ret);
		var g = ret2._g;
		var order = ret2._order;
		this.h = g.modPow(order.divide(pi.value), this.m);
		this.q = order.divide(pi.value);

		return {_g:g, _m: this.m};
	};
	
	this.extractAnswer = function(ge) {
		var base = this.pi.base;
		var exp = this.pi.exp;
		var orderH = this.pi.value;
		var beta = ge.modPow(this.q, this.m);
		var ans = phSpecializedPholigHellman(this.h, beta, orderH, this.m, base, exp);
		return ans;
	};
}



/*
var rems = [new BigInteger("33", 10),new BigInteger("23", 10), 
            new BigInteger("49", 10),new BigInteger("45", 10)];
var mods = [new BigInteger("7", 10),new BigInteger("11", 10), 
            new BigInteger("13", 10),new BigInteger("19", 10)];

var e = ChineseRemainder(rems, mods);
print(e.toString());
*/

/*
var client = new pClient();
var pi = {value:new BigInteger("11", 10), 
		base:new BigInteger("11", 10), exp:new BigInteger("1", 10)};
var len = 12;
var msg = client.generateQuery(pi, len);
print("g=" + msg._g);
print("m=" + msg._m);

var e = new BigInteger("17183", 10);
var ge = msg._g.modPow(e, msg._m);
print("ge=" + ge.toString());

var ans = client.extractAnswer(ge);
print("ans=" + ans.toString());
*/



while (1) {
var pi = {value:new BigInteger("49", 10), 
		base:new BigInteger("7", 10), exp:new BigInteger("2", 10)};

var ret = grGetPrimes(pi, 12);

var p1 = ret._p1;
var p2 = ret._p2;
print("pi="+pi.value.toString());
print("<br/>");
print("p1="+p1.toString());
print("=" + "2*" + pi.value.toString() + "*" + ret._q1.toString() +"+1");
print("<br/>");
print("p2=" + p2.toString());
print("=" + "2*" + ret._d.toString() + "*" + ret._q2.toString() +"+1");
print("(d=" + ret._d.toString() + ")");
print("<br/>");

var m = p1.clone().multiply(p2);
print("m=" + m.toString());
print("<br/>");

var ret2 = grSelectG(m, pi, ret);
var g = ret2._g;
var order = ret2._order;

print("g=" + ret2._g.toString());
print("<br/>");
print("order=" + ret2._order.toString());
print("<br/>");

var h = g.modPow(order.divide(pi.value), m);
print("h=" + h.toString());
print("<br/>");
var q = order.divide(pi.value);
print("q=" + q.toString());
print("<br/><br/>");

var e = new BigInteger("2736144", 10);
var ge = g.modPow(e, m);
print("ge=" + ge.toString());
print("<br/>");


var base = pi.base;
var exp = pi.exp;
var orderH = pi.value;
var beta = ge.modPow(q, m);
print("ge^q=" + beta.toString());
print("<br/>");
var ans = phSpecializedPholigHellman(h, beta, orderH, m, base, exp);
print("ans=log_h ge^q= " + ans.toString());
print("<br/>");
}


