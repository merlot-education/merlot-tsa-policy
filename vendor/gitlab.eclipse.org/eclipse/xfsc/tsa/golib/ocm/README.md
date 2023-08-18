# Go client for the OCM service

This go package contains client for communication with the OCM service.

### Installation

```shell
go get gitlab.eclipse.org/eclipse/xfsc/tsa/golib/ocm@latest
```

###Usage

In order to use this package you must import it in your application and
instantiate the client given the OCM service address like this:

```
import "gitlab.eclipse.org/eclipse/xfsc/tsa/golib/ocm"

func main() {
    client := ocm.New(ocmAddress)
}
```

###License

See [LICENSE](../LICENSE) for the full license.