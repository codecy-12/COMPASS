from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from ..schema import AuditEvent, HandleIdentity, ObjectKind
from ..util import parse_int


FD_ARGUMENTS = ("fd", "sockfd", "oldfd", "dirfd")
FILE_OPEN = {"open", "open64", "openat", "openat64", "openat2", "creat"}
SOCKET_CREATE = {"socket", "accept", "accept4"}
DUPLICATE = {"dup", "dup2", "dup3", "fcntl"}
CLOSE = {"close"}


class VersionedHandleMap:
    """Maps each descriptor use to the object generation valid at that event."""

    def __init__(self) -> None:
        self._active: Dict[Tuple[int, int], HandleIdentity] = {}
        self._generation: Dict[Tuple[int, int], int] = {}

    def active(self, pid: int, fd: int) -> Optional[HandleIdentity]:
        return self._active.get((pid, fd))

    def resolve_event(self, event: AuditEvent) -> AuditEvent:
        syscall = event.syscall
        pid = event.pid
        result = parse_int(event.result, -1)
        if syscall in FILE_OPEN and result is not None and result >= 0:
            path = str(event.args.get("path", event.args.get("name", event.args.get("pathname", ""))))
            event.handle = self._create(pid, result, ObjectKind.FILE, self._object_hint(event) or "file:%s" % (path or event.id))
        elif syscall == "socket" and result is not None and result >= 0:
            event.handle = self._create(
                pid, result, ObjectKind.SOCKET, self._object_hint(event) or "socket:%s" % event.id
            )
        elif syscall in {"accept", "accept4"} and result is not None and result >= 0:
            listener_fd = self._event_fd(event)
            listener = self.active(pid, listener_fd) if listener_fd is not None else None
            peer = str(event.args.get("peer", event.args.get("addr", "")))
            object_id = self._object_hint(event) or "accepted:%s:%s:%s" % (listener.object_id if listener else event.id, peer, event.id)
            event.handle = self._create(pid, result, ObjectKind.SOCKET, object_id)
            event.metadata["listener_handle"] = listener.object_id if listener else ""
        elif syscall in {"pipe", "pipe2", "socketpair"} and self._successful(event):
            fds = self._pair_fds(event)
            kind = ObjectKind.SOCKET if syscall == "socketpair" else ObjectKind.PIPE
            object_id = "%s:%s" % (syscall, event.id)
            identities = [self._create(pid, fd, kind, object_id) for fd in fds]
            if identities:
                event.handle = identities[0]
                event.metadata["created_handles"] = [item.__dict__ for item in identities]
        elif syscall in DUPLICATE and result is not None and result >= 0 and (
            syscall != "fcntl" or event.args.get("cmd") in {0, 1030, "F_DUPFD", "F_DUPFD_CLOEXEC"}
        ):
            source_fd = parse_int(event.args.get("oldfd", event.args.get("fd")), -1)
            source = self.active(pid, int(source_fd)) if source_fd is not None and source_fd >= 0 else None
            kind = source.kind if source else ObjectKind.UNKNOWN
            object_id = source.object_id if source else "dup:%s" % event.id
            event.handle = source if source is not None and source_fd == result else self._create(pid, result, kind, object_id)
        else:
            fd = self._event_fd(event)
            if fd is not None and fd >= 0:
                event.handle = self.active(pid, fd)
                hint = self._object_hint(event)
                if event.handle is not None and hint and event.handle.object_id != hint:
                    if event.handle.object_id.split(":", 1)[0] == hint.split(":", 1)[0]:
                        event.handle = self._create(pid, fd, event.handle.kind, hint)
                    else:
                        event.handle = HandleIdentity(pid, fd, event.handle.generation, event.handle.kind, hint)
                        self._active[(pid, fd)] = event.handle
                elif event.handle is None and hint:
                    event.handle = self._create(pid, fd, ObjectKind.UNKNOWN, hint)

        if syscall in CLOSE:
            fd = self._event_fd(event)
            if fd is not None:
                if event.handle is None:
                    event.handle = self.active(pid, fd)
                if self._successful(event):
                    self._active.pop((pid, fd), None)
        child_pid = parse_int(event.metadata.get("child_pid"), None)
        if syscall in {"clone", "clone3", "fork", "vfork"} and child_pid and child_pid > 0:
            self.inherit(pid, child_pid)
        return event

    def inherit(self, parent_pid: int, child_pid: int) -> None:
        for (pid, fd), identity in list(self._active.items()):
            if pid != parent_pid:
                continue
            generation = self._next_generation(child_pid, fd)
            self._active[(child_pid, fd)] = HandleIdentity(
                pid=child_pid,
                fd=fd,
                generation=generation,
                kind=identity.kind,
                object_id=identity.object_id,
            )

    def snapshot(self) -> List[HandleIdentity]:
        return sorted(self._active.values(), key=lambda item: (item.pid, item.fd))

    def _create(self, pid: int, fd: int, kind: ObjectKind, object_id: str) -> HandleIdentity:
        identity = HandleIdentity(
            pid=pid,
            fd=fd,
            generation=self._next_generation(pid, fd),
            kind=kind,
            object_id=object_id,
        )
        self._active[(pid, fd)] = identity
        return identity

    def _next_generation(self, pid: int, fd: int) -> int:
        key = (pid, fd)
        value = self._generation.get(key, 0) + 1
        self._generation[key] = value
        return value

    @staticmethod
    def _successful(event: AuditEvent) -> bool:
        result = parse_int(event.result, -1)
        return result is not None and result >= 0

    @staticmethod
    def _event_fd(event: AuditEvent) -> Optional[int]:
        for key in FD_ARGUMENTS:
            value = parse_int(event.args.get(key), None)
            if value is not None:
                return value
        return None

    @staticmethod
    def _pair_fds(event: AuditEvent) -> List[int]:
        raw = event.args.get("fds", event.args.get("fd_pair", []))
        if isinstance(raw, (list, tuple)):
            return [int(value) for value in raw[:2]]
        if isinstance(raw, str):
            values = raw.strip("[]() ").split(",")
            return [int(value.strip(), 0) for value in values[:2] if value.strip()]
        return []

    @staticmethod
    def _object_hint(event: AuditEvent) -> str:
        for key in ("object_id", "socket_cookie", "inode", "fd_name", "tuple"):
            value = event.args.get(key)
            if value not in (None, ""):
                if key == "fd_name" and str(value).startswith("/"):
                    return "file:%s" % value
                return "%s:%s" % (key, value)
        endpoints = [event.args.get(key) for key in ("client_ip", "client_port", "server_ip", "server_port")]
        if any(value not in (None, "") for value in endpoints):
            return "socket-tuple:%s" % ":".join(str(value or "") for value in endpoints)
        return ""
