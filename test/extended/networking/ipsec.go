package networking

import (
	"context"
	"fmt"
	"time"

	configv1 "github.com/openshift/api/config/v1"
	mcfgv1 "github.com/openshift/api/machineconfiguration/v1"
	v1 "github.com/openshift/api/operator/v1"
	exutil "github.com/openshift/origin/test/extended/util"
	"golang.org/x/sync/errgroup"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	admissionapi "k8s.io/pod-security-admission/api"

	g "github.com/onsi/ginkgo/v2"
	o "github.com/onsi/gomega"
)

const (
	// tcpdumpESPFilter can be used to filter out IPsec packets destined to target node.
	tcpdumpESPFilter = "esp or udp port 4500 and src %s and dst %s"
	// tcpdumpGeneveFilter can be used to filter out Geneve encapsulated packets destined to target node.
	tcpdumpGeneveFilter          = "udp port 6081 and src %s and dst %s"
	masterIPsecMachineConfigName = "80-ipsec-master-extensions"
	workerIPSecMachineConfigName = "80-ipsec-worker-extensions"
)

// configureIPsec helps to rollout specified IPsecConfig on the cluster.
func configureIPsec(oc *exutil.CLI, ipsecConfig *v1.IPsecConfig) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		network, err := oc.AdminOperatorClient().OperatorV1().Networks().Get(context.Background(), "cluster", metav1.GetOptions{})
		if err != nil {
			return err
		}
		network.Spec.DefaultNetwork.OVNKubernetesConfig.IPsecConfig = ipsecConfig
		_, err = oc.AdminOperatorClient().OperatorV1().Networks().Update(context.Background(), network, metav1.UpdateOptions{})
		return err
	})
}

// configureIPsec helps to rollout specified IPsec Mode on the cluster. If the cluster is already configured with specified mode, then
// this is almost like no-op for the cluster.
func configureIPsecMode(oc *exutil.CLI, ipsecMode v1.IPsecMode) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		network, err := oc.AdminOperatorClient().OperatorV1().Networks().Get(context.Background(), "cluster", metav1.GetOptions{})
		if err != nil {
			return err
		}
		if network.Spec.DefaultNetwork.OVNKubernetesConfig.IPsecConfig == nil {
			network.Spec.DefaultNetwork.OVNKubernetesConfig.IPsecConfig = &v1.IPsecConfig{Mode: ipsecMode}
		} else if network.Spec.DefaultNetwork.OVNKubernetesConfig.IPsecConfig.Mode != ipsecMode {
			network.Spec.DefaultNetwork.OVNKubernetesConfig.IPsecConfig.Mode = ipsecMode
		} else {
			// No changes to existing mode, return without updating networks.
			return nil
		}
		_, err = oc.AdminOperatorClient().OperatorV1().Networks().Update(context.Background(), network, metav1.UpdateOptions{})
		return err
	})
}

func getIPsecConfig(oc *exutil.CLI) (*v1.IPsecConfig, error) {
	network, err := oc.AdminOperatorClient().OperatorV1().Networks().Get(context.Background(), "cluster", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	ipsecConfig := network.Spec.DefaultNetwork.OVNKubernetesConfig.IPsecConfig
	if ipsecConfig != nil {
		ipsecConfig = ipsecConfig.DeepCopy()
	}
	return ipsecConfig, nil
}

// ensureIPsecEnabled this function ensure IPsec is enabled by making sure ovn-ipsec-host daemonset
// is completely ready on the cluster and cluster operators are coming back into ready state
// once ipsec rollout is complete.
func ensureIPsecEnabled(oc *exutil.CLI) (bool, error) {
	mcComplete, err := ensureIPsecMachineConfigRolloutComplete(oc)
	if !mcComplete {
		return mcComplete, err
	}
	for {
		running, err := isIPsecDaemonSetRunning(oc)
		if err != nil && !isConnReset(err) {
			return false, err
		}
		if running {
			ready, err := isClusterOperatorsReady((oc))
			if err != nil && !isConnReset(err) {
				return false, err
			}
			if ready {
				return true, nil
			}
		}
		time.Sleep(60 * time.Second)
	}
}

// ensureIPsecMachineConfigRolloutComplete this function ensures ipsec machine config extension is rolled out
// on all of master and worked nodes and cluster operators are coming back into ready state
// once ipsec rollout is complete.
func ensureIPsecMachineConfigRolloutComplete(oc *exutil.CLI) (bool, error) {
	for {
		done, err := isMachineConfigPoolReadyWithIPsec(oc)
		if err != nil && !isConnReset(err) {
			return false, err
		}
		if done {
			ready, err := isClusterOperatorsReady((oc))
			if err != nil && !isConnReset(err) {
				return false, err
			}
			if ready {
				return true, nil
			}
		}
		time.Sleep(60 * time.Second)
	}
}

// ensureIPsecDisabled this function ensure IPsec is disabled by making sure ovn-ipsec-host daemonset
// is completely removed from the cluster and cluster operators are coming back into ready state
// once ipsec rollout is complete.
func ensureIPsecDisabled(oc *exutil.CLI) (bool, error) {
	for {
		mcpReady, err := isMachineConfigPoolReadyWithoutIPsec(oc)
		if err != nil && !isConnReset(err) {
			return false, err
		}
		if mcpReady {
			running, err := isIPsecDaemonSetRunning(oc)
			if err != nil && !isConnReset(err) {
				return false, err
			}
			if !running {
				ready, err := isClusterOperatorsReady((oc))
				if err != nil && !isConnReset(err) {
					return false, err
				}
				if ready {
					return true, nil
				}
			}
		}
		time.Sleep(60 * time.Second)
	}
}

// This checks master and worker machine config pool status are set with ipsec extension which
// confirms extension is successfully rolled out on all nodes.
func isMachineConfigPoolReadyWithIPsec(oc *exutil.CLI) (bool, error) {
	masterWithIPsec, err := isMasterMachineConfigPoolWithIPsec(oc)
	if err != nil {
		return false, err
	}
	workerWithIPsec, err := isWorkerMachineConfigPoolReadyWithIPsec(oc)
	if err != nil {
		return false, err
	}
	return masterWithIPsec && workerWithIPsec, nil
}

// This checks master and worker machine config pool status are set without ipsec extension
// which confirms extension is successfully removed from all nodes.
func isMachineConfigPoolReadyWithoutIPsec(oc *exutil.CLI) (bool, error) {
	masterWithIPsec, err := isMasterMachineConfigPoolWithIPsec(oc)
	if err != nil {
		return false, err
	}
	workerWithIPsec, err := isWorkerMachineConfigPoolReadyWithIPsec(oc)
	if err != nil {
		return false, err
	}
	return !masterWithIPsec && !workerWithIPsec, nil
}

func isMasterMachineConfigPoolWithIPsec(oc *exutil.CLI) (bool, error) {
	masterMCPool, err := oc.MachineConfigurationClient().MachineconfigurationV1().MachineConfigPools().Get(context.Background(),
		"master", metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to get ipsec machine config pool for master: %v", err)
	}
	return hasSourceInMachineConfigStatus(masterMCPool.Status, masterIPsecMachineConfigName), nil
}

func isWorkerMachineConfigPoolReadyWithIPsec(oc *exutil.CLI) (bool, error) {
	workerMCPool, err := oc.MachineConfigurationClient().MachineconfigurationV1().MachineConfigPools().Get(context.Background(),
		"worker", metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to get ipsec machine config pool for worker: %v", err)
	}
	return hasSourceInMachineConfigStatus(workerMCPool.Status, workerIPSecMachineConfigName), nil
}

func hasSourceInMachineConfigStatus(machineConfigStatus mcfgv1.MachineConfigPoolStatus, machineConfigName string) bool {
	for _, source := range machineConfigStatus.Configuration.Source {
		if source.Name == machineConfigName {
			return true
		}
	}
	return false
}

// isClusterOperatorsReady returns true when every cluster operator is with available state and neither in degraded
// nor in progressing state, otherwise returns false.
func isClusterOperatorsReady(oc *exutil.CLI) (bool, error) {
	cos, err := oc.AdminConfigClient().ConfigV1().ClusterOperators().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	for _, co := range cos.Items {
		available, degraded, progressing := false, true, true
		for _, condition := range co.Status.Conditions {
			isConditionTrue := condition.Status == configv1.ConditionTrue
			switch condition.Type {
			case configv1.OperatorAvailable:
				available = isConditionTrue
			case configv1.OperatorDegraded:
				degraded = isConditionTrue
			case configv1.OperatorProgressing:
				progressing = isConditionTrue
			}
		}
		isCOReady := available && !degraded && !progressing
		if !isCOReady {
			return false, nil
		}
	}
	return true, nil
}

func isIPsecDaemonSetRunning(oc *exutil.CLI) (bool, error) {
	ipsecDS, err := oc.AdminKubeClient().AppsV1().DaemonSets("openshift-ovn-kubernetes").Get(context.Background(), "ovn-ipsec-host", metav1.GetOptions{})
	if err != nil && apierrors.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	// Be sure that it has ovn-ipsec-host pod running in each node.
	ready := ipsecDS.Status.DesiredNumberScheduled == ipsecDS.Status.NumberReady
	return ready, nil
}

var _ = g.Describe("[sig-network][Feature:IPsec]", g.Ordered, func() {

	oc := exutil.NewCLIWithPodSecurityLevel("ipsec", admissionapi.LevelPrivileged)
	f := oc.KubeFramework()

	// IPsec is supported only with OVN-Kubernetes CNI plugin.
	InOVNKubernetesContext(func() {
		// The tests chooses two different nodes. Each node has two pods running, one is ping pod and another one is tcpdump pod.
		// The ping pod is used to send ping packet to its peer pod whereas tcpdump hostnetworked pod used for capturing the packet
		// at node's primary interface. Based on the IPsec configuration on the cluster, the captured packet on the host interface
		// must be either geneve or esp packet type.
		type testNodeConfig struct {
			pingPod    *corev1.Pod
			tcpdumpPod *corev1.Pod
			hostInf    string
			nodeName   string
		}
		type testConfig struct {
			ipsecConfig   *v1.IPsecConfig
			srcNodeConfig *testNodeConfig
			dstNodeConfig *testNodeConfig
		}
		// The config object contains test configuration that can be leveraged by each ipsec test.
		var config *testConfig
		// This function helps to generate ping traffic from src pod to dst pod and at the same captures its
		// node traffic on both src and dst node.
		pingAndCheckNodeTraffic := func(src, dst *testNodeConfig, ipsecTraffic bool) error {
			tcpDumpSync := errgroup.Group{}
			pingSync := errgroup.Group{}
			// use tcpdump pod's ip address it's a node ip address because it's a hostnetworked pod.
			srcNodeTrafficFilter := fmt.Sprintf(tcpdumpGeneveFilter, src.tcpdumpPod.Status.PodIP, dst.tcpdumpPod.Status.PodIP)
			dstNodeTrafficFilter := fmt.Sprintf(tcpdumpGeneveFilter, dst.tcpdumpPod.Status.PodIP, src.tcpdumpPod.Status.PodIP)
			if ipsecTraffic {
				srcNodeTrafficFilter = fmt.Sprintf(tcpdumpESPFilter, src.tcpdumpPod.Status.PodIP, dst.tcpdumpPod.Status.PodIP)
				dstNodeTrafficFilter = fmt.Sprintf(tcpdumpESPFilter, dst.tcpdumpPod.Status.PodIP, src.tcpdumpPod.Status.PodIP)
			}
			checkSrcNodeTraffic := func(src *testNodeConfig) error {
				_, err := oc.AsAdmin().Run("exec").Args(src.tcpdumpPod.Name, "-n", src.tcpdumpPod.Namespace, "--",
					"timeout", "10", "tcpdump", "-i", src.hostInf, "-c", "1", "-v", "--direction=out", srcNodeTrafficFilter).Output()
				return err
			}
			checkDstNodeTraffic := func(dst *testNodeConfig) error {
				_, err := oc.AsAdmin().Run("exec").Args(dst.tcpdumpPod.Name, "-n", dst.tcpdumpPod.Namespace, "--",
					"timeout", "10", "tcpdump", "-i", dst.hostInf, "-c", "1", "-v", "--direction=out", dstNodeTrafficFilter).Output()
				return err
			}
			pingTestFromPod := func(src, dst *testNodeConfig) error {
				_, err := oc.AsAdmin().Run("exec").Args(src.pingPod.Name, "-n", src.pingPod.Namespace, "--",
					"ping", "-c", "3", dst.pingPod.Status.PodIP).Output()
				return err
			}
			tcpDumpSync.Go(func() error {
				err := checkSrcNodeTraffic(src)
				if err != nil {
					return fmt.Errorf("error capturing traffic on the source node: %v", err)
				}
				return nil
			})
			tcpDumpSync.Go(func() error {
				err := checkDstNodeTraffic(dst)
				if err != nil {
					return fmt.Errorf("error capturing traffic on the dst node: %v", err)
				}
				return nil
			})
			pingSync.Go(func() error {
				return pingTestFromPod(src, dst)
			})
			// Wait for both ping and tcpdump capture complete and check the results.
			pingErr := pingSync.Wait()
			err := tcpDumpSync.Wait()
			if err != nil {
				return fmt.Errorf("failed to detect underlay traffic on node, node tcpdump err: %v, ping err: %v", err, pingErr)
			}
			return nil
		}

		setupTestPods := func(config *testConfig) error {
			tcpdumpImage, err := exutil.DetermineImageFromRelease(oc, "network-tools")
			o.Expect(err).NotTo(o.HaveOccurred())
			createSync := errgroup.Group{}
			createSync.Go(func() error {
				var err error
				config.srcNodeConfig.tcpdumpPod, err = launchHostNetworkedPodForTCPDump(f, tcpdumpImage, config.srcNodeConfig.nodeName, "ipsec-tcpdump-hostpod-")
				if err != nil {
					return err
				}
				config.srcNodeConfig.pingPod, err = createPod(f.ClientSet, f.Namespace.Name, "ipsec-test-srcpod-", func(p *corev1.Pod) {
					p.Spec.NodeName = config.srcNodeConfig.nodeName
				})
				return err
			})
			createSync.Go(func() error {
				var err error
				config.dstNodeConfig.tcpdumpPod, err = launchHostNetworkedPodForTCPDump(f, tcpdumpImage, config.dstNodeConfig.nodeName, "ipsec-tcpdump-hostpod-")
				if err != nil {
					return err
				}
				config.dstNodeConfig.pingPod, err = createPod(f.ClientSet, f.Namespace.Name, "ipsec-test-dstpod-", func(p *corev1.Pod) {
					p.Spec.NodeName = config.dstNodeConfig.nodeName
				})
				return err
			})
			return createSync.Wait()
		}

		cleanupTestPods := func(config *testConfig) {
			err := removePod(f.ClientSet, config.srcNodeConfig.pingPod)
			o.Expect(err).NotTo(o.HaveOccurred())
			config.srcNodeConfig.pingPod = nil
			err = removePod(f.ClientSet, config.srcNodeConfig.tcpdumpPod)
			o.Expect(err).NotTo(o.HaveOccurred())
			config.srcNodeConfig.tcpdumpPod = nil

			err = removePod(f.ClientSet, config.dstNodeConfig.pingPod)
			o.Expect(err).NotTo(o.HaveOccurred())
			config.dstNodeConfig.pingPod = nil
			err = removePod(f.ClientSet, config.dstNodeConfig.tcpdumpPod)
			o.Expect(err).NotTo(o.HaveOccurred())
			config.dstNodeConfig.tcpdumpPod = nil
		}

		checkForGeneveOnlyTraffic := func(config *testConfig) {
			err := setupTestPods(config)
			o.Expect(err).NotTo(o.HaveOccurred())
			defer func() {
				cleanupTestPods(config)
			}()
			err = pingAndCheckNodeTraffic(config.srcNodeConfig, config.dstNodeConfig, false)
			o.Expect(err).NotTo(o.HaveOccurred())
			err = pingAndCheckNodeTraffic(config.srcNodeConfig, config.dstNodeConfig, true)
			o.Expect(err).To(o.HaveOccurred())
		}

		checkForESPOnlyTraffic := func(config *testConfig) {
			err := setupTestPods(config)
			o.Expect(err).NotTo(o.HaveOccurred())
			defer func() {
				cleanupTestPods(config)
			}()
			err = pingAndCheckNodeTraffic(config.srcNodeConfig, config.dstNodeConfig, true)
			o.Expect(err).NotTo(o.HaveOccurred())
			err = pingAndCheckNodeTraffic(config.srcNodeConfig, config.dstNodeConfig, false)
			o.Expect(err).To(o.HaveOccurred())
		}

		g.BeforeAll(func() {
			// Set up the config object with existing IPsecConfig, setup testing config on
			// the selected nodes.
			ipsecConfig, err := getIPsecConfig(oc)
			o.Expect(err).NotTo(o.HaveOccurred())

			srcNode, dstNode := &testNodeConfig{}, &testNodeConfig{}
			config = &testConfig{ipsecConfig: ipsecConfig, srcNodeConfig: srcNode, dstNodeConfig: dstNode}
		})

		g.BeforeEach(func() {
			o.Expect(config).NotTo(o.BeNil())
			g.By("Choosing 2 different nodes")
			node1, node2, err := findAppropriateNodes(f, DIFFERENT_NODE)
			o.Expect(err).NotTo(o.HaveOccurred())
			config.srcNodeConfig.nodeName = node1.Name
			config.srcNodeConfig.hostInf, err = findBridgePhysicalInterface(oc, node1.Name, "br-ex")
			o.Expect(err).NotTo(o.HaveOccurred())
			config.dstNodeConfig.nodeName = node2.Name
			config.dstNodeConfig.hostInf, err = findBridgePhysicalInterface(oc, node2.Name, "br-ex")
			o.Expect(err).NotTo(o.HaveOccurred())
		})

		g.AfterEach(func() {
			// Restore the cluster back into original state after running all the tests.
			g.By("restoring ipsec config into original state")
			err := configureIPsec(oc, config.ipsecConfig)
			o.Expect(err).NotTo(o.HaveOccurred())
			if config.ipsecConfig == nil {
				waitForIPsecConfigToComplete(oc, v1.IPsecModeDisabled)
			} else {
				waitForIPsecConfigToComplete(oc, config.ipsecConfig.Mode)
			}
		})

		g.It("ensure traffic between local pod to a remote pod is IPsec encrypted when IPsecMode configured in Full mode [apigroup:config.openshift.io] [Suite:openshift/network/ipsec]", func() {
			o.Expect(config).NotTo(o.BeNil())
			g.By("validate pod traffic before changing IPsec configuration")
			// Ensure pod traffic is working before rolling out IPsec configuration.
			if config.ipsecConfig == nil || config.ipsecConfig.Mode == v1.IPsecModeDisabled {
				checkForGeneveOnlyTraffic(config)
			} else {
				checkForESPOnlyTraffic(config)
			}

			g.By("configure IPsec in Full mode and validate pod traffic")
			// Rollout IPsec with Full mode which sets up IPsec in OVS dataplane which makes pod traffic across nodes
			// would be always ipsec encrypted.
			err := configureIPsecMode(oc, v1.IPsecModeFull)
			o.Expect(err).NotTo(o.HaveOccurred())
			waitForIPsecConfigToComplete(oc, v1.IPsecModeFull)
			checkForESPOnlyTraffic(config)
		})

		g.It("ensure traffic between local pod to a remote pod is not IPsec encrypted when IPsecMode configured in External mode [apigroup:config.openshift.io] [Suite:openshift/network/ipsec]", func() {
			o.Expect(config).NotTo(o.BeNil())
			g.By("validate pod traffic before changing IPsec configuration")
			// Ensure pod traffic is working before rolling out IPsec configuration.
			if config.ipsecConfig == nil || config.ipsecConfig.Mode == v1.IPsecModeDisabled {
				checkForGeneveOnlyTraffic(config)
			} else {
				checkForESPOnlyTraffic(config)
			}

			g.By("configure IPsec in External mode and validate pod traffic")
			// Change IPsec mode to External and packet capture on the node's interface
			// must be geneve encapsulated ones.
			err := configureIPsecMode(oc, v1.IPsecModeExternal)
			o.Expect(err).NotTo(o.HaveOccurred())
			waitForIPsecConfigToComplete(oc, v1.IPsecModeExternal)
			checkForGeneveOnlyTraffic(config)
		})

		g.It("ensure traffic between local pod to a remote pod is not IPsec encrypted when IPsec is Disabled [apigroup:config.openshift.io] [Suite:openshift/network/ipsec]", func() {
			o.Expect(config).NotTo(o.BeNil())
			g.By("validate pod traffic before changing IPsec configuration")
			// Ensure pod traffic is working before rolling out IPsec configuration.
			if config.ipsecConfig == nil || config.ipsecConfig.Mode == v1.IPsecModeDisabled {
				checkForGeneveOnlyTraffic(config)
			} else {
				checkForESPOnlyTraffic(config)
			}

			g.By("configure IPsec in Disabled mode and validate pod traffic")
			// Configure IPsec mode to Disabled and packet capture on the node's interface
			// must be geneve encapsulated ones.
			err := configureIPsecMode(oc, v1.IPsecModeDisabled)
			o.Expect(err).NotTo(o.HaveOccurred())
			waitForIPsecConfigToComplete(oc, v1.IPsecModeDisabled)
			checkForGeneveOnlyTraffic(config)
		})
	})
})

func waitForIPsecConfigToComplete(oc *exutil.CLI, ipsecMode v1.IPsecMode) {
	switch ipsecMode {
	case v1.IPsecModeDisabled:
		disabled, err := ensureIPsecDisabled(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(disabled).Should(o.Equal(true))
	case v1.IPsecModeExternal:
		ready, err := ensureIPsecMachineConfigRolloutComplete(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(ready).Should(o.Equal(true))
	case v1.IPsecModeFull:
		enabled, err := ensureIPsecEnabled(oc)
		o.Expect(err).NotTo(o.HaveOccurred())
		o.Expect(enabled).Should(o.Equal(true))
	}
}
