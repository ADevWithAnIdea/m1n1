# SPDX-License-Identifier: GPL-2.0-only
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from m1n1.drm_shim import g17g_backend as backend, g17g_postcontrol as post
from m1n1.drm_shim.g17g_render_queue import (transport_head, transport_pages, recreate_transport,
                                      mixed_transport_addresses, mixed_transport_pages)


class TestRenderTransport(unittest.TestCase):
    def test_mixed_recreation_preserves_compute_bytes_and_logical_progress(self):
        from m1n1.drm_shim import g17g
        from m1n1.drm_shim.g17g_compute_queue import transport_state
        layout = backend._mixed_render_layout(compute_predecessor=True)
        owned = {dva: bytes((i+1,))*0x4000 for i,dva in enumerate(mixed_transport_addresses())}
        bodies = mixed_transport_pages(owned)
        for index in (1,2):
            offset = index*g17g.QUEUE_RECORD_STRIDE
            self.assertEqual(bodies[post.QUEUE_PAGE][offset+0x28:offset+0x40],
                             owned[post.QUEUE_PAGE][offset+0x28:offset+0x40])
        allowed = {dva: bytearray(0x4000) for dva in owned}
        for kind in ('tiling','fragment'):
            for address, size in (
                (post.QUEUE_PAGE+layout[kind+'_physical_queue_index']*g17g.QUEUE_RECORD_STRIDE,128),
                (layout[kind+'_pointer'],len(g17g.build_pointer_block())),
                (layout[kind+'_item_ring'],backend.RENDER_INNER_RING_ITEM_COUNT*8)):
                for off in range(size):
                    allowed[(address+off)&-0x4000][(address+off)%0x4000] = 1
        for dva in owned:
            self.assertTrue(all(a == b or permit for a,b,permit in zip(owned[dva],bodies[dva],allowed[dva])))
        before = dict(queue=[1278]*2,pointers=[[1278]*3]*2,channels=[[170]*3]*2)
        after = dict(queue=[0]*2,pointers=[[0]*3]*2,channels=[[170]*3]*2)
        for alias in (False,True):
            pages = {dva:0x100000+i*0x4000 for i,dva in enumerate(owned)}
            old = dict(pages)
            maps = dict(pages)
            runtime = SimpleNamespace(state='complete',completed=2,render_completed=426,
                root=1,boot=SimpleNamespace(firmware_roots={0:1}),pages=pages,
                context=dict(pages={0:old[post.QUEUE_PAGE]} if alias else {}),queue_addresses={},
                service_cursor=6,channel_state=lambda:(6,)*3,
                mixed_retirement=Mock(side_effect=(before,after)),
                retirement_state=Mock(return_value=transport_state(2)),
                read_fields=Mock(return_value=owned),ack_retired_reports=Mock(return_value={}),
                alloc=Mock(return_value=0x200000),publish=Mock(),flush_tables=Mock(),
                evidence={},u=None,p=None,iface=None)
            runtime.boot.submission_owner = runtime
            runtime.uat = SimpleNamespace(iotranslate_root=lambda root,dva,size:[(maps[dva],size)],
                iounmap_root=lambda root,dva,size:size,
                iomap_at_root=lambda root,dva,pa,size,**flags:maps.update({dva:pa}))
            with patch('m1n1.drm_shim.g17g_render_queue.write_publications') as publish:
                if alias:
                    with self.assertRaisesRegex(RuntimeError,'context alias'):
                        recreate_transport(runtime,427,mixed=True)
                    runtime.alloc.assert_not_called()
                    publish.assert_not_called()
                    self.assertEqual(old,pages)
                else:
                    result = recreate_transport(runtime,427,mixed=True)
                    self.assertEqual((runtime.completed,runtime.render_completed,runtime.render_transport_start),(2,426,427))
                    self.assertEqual(result['compute_before'],result['compute_after'])
                    self.assertEqual(len(result['rebinds']),5)
                    self.assertEqual({row['old_pa'] for row in result['rebinds']},set(old.values()))
                    runtime.alloc.assert_called_once_with(5*0x4000)

    def test_finite_heads_preserve_global_timeline(self):
        self.assertEqual(transport_head(426), 1278)
        self.assertEqual(transport_head(426, 427), 0)
        self.assertEqual(transport_head(427, 427), 3)
        self.assertEqual(transport_head(852, 427), 1278)
        for completed, start in ((427, 1), (853, 427), (425, 427), (1, 0), (True, 1)):
            with self.assertRaises(ValueError): transport_head(completed, start)

    def test_recreation_changes_only_owned_transport_and_keeps_old_backing(self):
        for failure in (None, "foreign_root", "not_quiescent", "fault", "partial_rebind", "flush"):
            with self.subTest(failure=failure):
                bodies = transport_pages(backend.PARTIAL_RENDER_TOKEN)
                self.assertEqual(set(bodies), {post.QUEUE_PAGE, post.QUEUE_POINTER_PAGE,
                    post.QUEUE_ITEM_RING_PAGE, post.QUEUE_ITEM_RING_PAGE + 0x4000})
                self.assertTrue(all(len(body) == 0x4000 for body in bodies.values()))
                pages = {dva: 0x100000 + index * 0x4000 for index, dva in enumerate(bodies)}
                pages[0xfffffc2001230000] = 0x300000
                old = dict(pages)
                maps = {(root, dva): [(pa, 0x4000)] for root in (1, 2, 3) for dva, pa in pages.items()}
                before = dict(queue=[1278] * 2, pointers=[[1278] * 3] * 2, channels=[[170] * 3] * 2)
                after = dict(queue=[0] * 2, pointers=[[0] * 3] * 2, channels=[[170] * 3] * 2)
                runtime = SimpleNamespace(state="complete", completed=426, root=1, partial_mode=True,
                    pages=pages, service_cursor=7, boot=SimpleNamespace(firmware_roots={0: 2, 1: 3}),
                    retirement=Mock(side_effect=(before, after)), channel_state=lambda: (7, 7, 7),
                    ack_retired_reports=Mock(return_value={},
                        side_effect=RuntimeError("unhandled fault report") if failure == "fault" else None),
                    alloc=Mock(return_value=0x200000),
                    publish=Mock(), flush_tables=Mock(
                        side_effect=OSError("table flush") if failure == "flush" else None),
                    u=None, p=None, iface=None, evidence={})
                runtime.boot.submission_owner = runtime
                def unmap(root, dva, size):
                    for root in (1, 2, 3): maps[root, dva] = [(None, size)]
                    return size
                def install(root, dva, pa, size, **flags):
                    if failure == "partial_rebind" and dva == post.QUEUE_POINTER_PAGE:
                        raise OSError("mapping transport interrupted")
                    for root in (1, 2, 3): maps[root, dva] = [(pa, size)]
                runtime.uat = SimpleNamespace(iotranslate_root=lambda root,dva,size: maps[root,dva],
                    iounmap_root=Mock(side_effect=unmap), iomap_at_root=Mock(side_effect=install))
                if failure == "foreign_root": maps[3, post.QUEUE_POINTER_PAGE] = [(0xdead0000, 0x4000)]
                if failure == "not_quiescent": before["queue"][1] -= 3
                with patch("m1n1.drm_shim.g17g_render_queue.write_publications") as write:
                    if failure in ("partial_rebind", "flush"):
                        with self.assertRaises(OSError): recreate_transport(runtime, 427)
                        self.assertEqual(runtime.state, "failed")
                        self.assertEqual(runtime.completed, 426)
                        self.assertFalse(hasattr(runtime, "transport_start"))
                        self.assertTrue(runtime.evidence["command_publication_started"])
                        evidence = runtime.evidence["transport_recreation"]
                        self.assertEqual(evidence["phase"],
                                         "replacement" if failure == "partial_rebind" else "table-flush")
                        self.assertEqual(len(evidence["rebinds"]), 1 if failure == "partial_rebind" else 4)
                        self.assertNotIn("after", evidence)
                        self.assertEqual(pages[0xfffffc2001230000], old[0xfffffc2001230000])
                        # A partially changed transport cannot be retried as
                        # a completed owner or silently allocate another epoch.
                        with self.assertRaisesRegex(RuntimeError, "completed owner"):
                            recreate_transport(runtime, 427)
                        runtime.alloc.assert_called_once_with(4 * 0x4000)
                        write.assert_called_once()
                    elif failure:
                        with self.assertRaises(RuntimeError): recreate_transport(runtime, 427)
                        runtime.alloc.assert_not_called()
                        write.assert_not_called()
                        runtime.uat.iounmap_root.assert_not_called()
                        self.assertEqual(pages, old)
                    else:
                        result = recreate_transport(runtime, 427)
                        self.assertEqual(runtime.transport_start, 427)
                        self.assertEqual(runtime.completed, 426)
                        self.assertEqual(runtime.state, "complete")
                        self.assertEqual(len(result["rebinds"]), 4)
                        self.assertEqual({dva for dva in old if old[dva] != pages[dva]}, set(bodies))
                        self.assertEqual({row["old_pa"] for row in result["rebinds"]},
                                         {old[dva] for dva in bodies})
                        self.assertEqual(set(pages.values()) & set(old.values()), {0x300000})


if __name__ == "__main__":
    unittest.main()
