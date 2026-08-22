# SPDX-License-Identifier: MIT
"""Check the two halves of a single-boot capture agree before replaying them.

A graft is only meaningful if the halves really are one submission: they should share the
four objects a pointer block names, occupy different ring/queue addresses, and between them
cover the render pages either half references.
"""
import json
import sys

D = sys.argv[1]

def load(name):
    return (json.load(open('%s/%s/target.json' % (D, name))),
            json.load(open('%s/%s/pages.json' % (D, name))))

def val(x):
    return int(x, 0) if isinstance(x, str) else int(x)

halves = {}
for name in ('TA_0', '3D_0'):
    t, pj = load(name)
    pages = pj['pages'] if isinstance(pj, dict) and 'pages' in pj else pj
    halves[name] = (t, pages)

for name, (t, pages) in halves.items():
    render = [p for p in pages if not (val(p['dva']) >> 42) & 1]
    q = (t.get('queues') or [{}])[0]
    print('%s: %d pages (%d render), producer %s -> %s, entry %s' % (
        name, len(pages), len(render), t.get('producer_before'),
        t.get('producer_after'), t.get('entry_index')))
    print('    outer  %#014x' % val(t['outer_dva']))
    print('    queue  %s' % (('%#014x' % val(q['queue_dva'])) if q.get('queue_dva') else '-'))
    print('    inner  %s' % (('%#014x' % val(q['inner_dva'])) if q.get('inner_dva') else '-'))
    print('    items  %s captured of %s' % (q.get('captured_inner_items'),
                                            q.get('requested_inner_items')))
    for p in render:
        print('    render %#014x' % val(p['dva']))

ta, ta_pages = halves['TA_0']
fr, fr_pages = halves['3D_0']

ta_set = {val(p['dva']) for p in ta_pages}
fr_set = {val(p['dva']) for p in fr_pages}
print()
print('pages in both halves: %d' % len(ta_set & fr_set))
for d in sorted(ta_set & fr_set):
    print('   shared %#014x' % d)
print('pages only in tiling: %d, only in fragment: %d'
      % (len(ta_set - fr_set), len(fr_set - ta_set)))

print()
same_outer = val(ta['outer_dva']) == val(fr['outer_dva'])
print('distinct outer records: %s' % (not same_outer))
tq = (ta.get('queues') or [{}])[0]
fq = (fr.get('queues') or [{}])[0]
if tq.get('queue_dva') and fq.get('queue_dva'):
    print('distinct queues: %s' % (val(tq['queue_dva']) != val(fq['queue_dva'])))
print('same producer index: %s' % (ta.get('producer_before') == fr.get('producer_before')))
te = sum(len(json.load(open('%s/%s/target.json' % (D, n)))
             .get('read_errors') or []) for n in ('TA_0', '3D_0'))
print('read errors across both halves: %d' % te)
