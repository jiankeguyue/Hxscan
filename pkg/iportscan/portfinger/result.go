package portfinger

type Result struct {
	Addr          string
	ServiceName   string
	ProbeName     string
	VendorProduct string
	Version       string
}
