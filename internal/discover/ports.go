package discover

// DiscoveryPorts are coverage-oriented TCP ports used to detect live hosts.
// Separate from findings ports — chosen to maximize "is anyone home?" signal.
var DiscoveryPorts = []int{
	80, 443, 22, 445, 139, 53, 8080, 8443, 3389, 5900, 25, 21,
}
