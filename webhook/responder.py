import logging
import threading
import time
from kubernetes import client, config

logger = logging.getLogger(__name__)


def load_k8s_client():
    """Load k8s config — in-cluster when running as a pod."""
    try:
        config.load_incluster_config()
        logger.info("Loaded in-cluster Kubernetes config")
    except config.ConfigException:
        config.load_kube_config()
        logger.info("Loaded local kubeconfig")
    return client.CoreV1Api()


def quarantine_pod(v1: client.CoreV1Api, pod_name: str, namespace: str) -> bool:
    """
    Add quarantine label to pod.
    A NetworkPolicy watching for this label will block all traffic.
    Returns True on success, False on failure.
    """
    try:
        body = {"metadata": {"labels": {"quarantine": "true"}}}
        v1.patch_namespaced_pod(
            name=pod_name,
            namespace=namespace,
            body=body
        )
        logger.warning(
            f"QUARANTINED pod={pod_name} ns={namespace} — network isolated"
        )
        return True
    except client.exceptions.ApiException as e:
        if e.status == 404:
            logger.error(f"Pod not found: {pod_name} in {namespace}")
        else:
            logger.error(f"Failed to quarantine {pod_name}: {e}")
        return False


def delete_pod(v1: client.CoreV1Api, pod_name: str, namespace: str) -> bool:
    """
    Delete the offending pod.
    Returns True on success, False on failure.
    """
    try:
        v1.delete_namespaced_pod(
            name=pod_name,
            namespace=namespace,
            body=client.V1DeleteOptions(grace_period_seconds=0)
        )
        logger.warning(
            f"DELETED pod={pod_name} ns={namespace}"
        )
        return True
    except client.exceptions.ApiException as e:
        if e.status == 404:
            logger.info(f"Pod already gone: {pod_name} in {namespace}")
            return True
        logger.error(f"Failed to delete {pod_name}: {e}")
        return False


def respond(v1: client.CoreV1Api, pod_name: str,
            namespace: str, priority: str, rule: str):
    """
    Tiered response based on alert severity:
      CRITICAL  → quarantine immediately + delete after 60s forensics window
      WARNING   → quarantine only (human reviews before deletion)
    """
    priority_upper = priority.upper()
    logger.warning(
        f"RESPONDING to rule='{rule}' priority={priority_upper} "
        f"pod={pod_name} ns={namespace}"
    )

    # Always quarantine first — cuts network immediately
    quarantine_pod(v1, pod_name, namespace)

    if priority_upper == "CRITICAL":
        # Schedule deletion after 60s forensics window
        def delayed_delete():
            logger.warning(
                f"Forensics window elapsed — deleting pod={pod_name}"
            )
            delete_pod(v1, pod_name, namespace)

        timer = threading.Timer(60.0, delayed_delete)
        timer.daemon = True
        timer.start()
        logger.warning(
            f"Pod {pod_name} will be deleted in 60 seconds"
        )
    else:
        logger.warning(
            f"WARNING severity — pod {pod_name} quarantined, "
            f"awaiting manual review"
        )