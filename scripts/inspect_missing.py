"""Inspect only the three user-reported missing lessons without exposing URLs."""
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from main import login_with_retry
from src.api.icourse import ICourseClient
from src.runtime import config

TARGETS = [('计算物理基础', '2026-09-24第6-8节'),
           ('电动力学', '2026-09-17第3-5节'),
           ('热力学与统计物理', '2026-09-07第6-8节')]

conn = sqlite3.connect(config.DB_PATH)
conn.row_factory = sqlite3.Row
client = ICourseClient(login_with_retry())
for title, lesson in TARGETS:
    courses = conn.execute('SELECT * FROM courses WHERE title LIKE ?',
                           ('%' + title + '%',)).fetchall()
    for course in courses:
        cid = course['course_id']
        print('TARGET COURSE', cid, course['title'], lesson, flush=True)
        rows = conn.execute('SELECT * FROM lectures WHERE course_id=? AND sub_title=?',
                            (cid, lesson)).fetchall()
        for row in rows:
            print('DATABASE', {k: row[k] for k in ('sub_id', 'processed_at', 'error_stage', 'error_msg', 'error_count')},
                  'transcript_chars', len(row['transcript'] or ''),
                  'summary_chars', len(row['summary'] or ''), flush=True)
            pages = conn.execute('SELECT COUNT(*), SUM(LENGTH(text)), MAX(created_sec) FROM ppt_pages WHERE sub_id=?',
                                 (row['sub_id'],)).fetchone()
            print('PPT DATABASE', tuple(pages), flush=True)
        detail = client.get_course_detail(cid)
        for lecture in detail['lectures']:
            if lecture['sub_title'] == lesson:
                sid = str(lecture['sub_id'])
                print('SOURCE', lecture, flush=True)
                print('PLAYABLE URL', bool(client.get_video_url(cid, sid)), flush=True)
                pages = client.get_ppt_list(cid, sid)
                print('SOURCE PPT', len(pages), 'last_second', max((p['created_sec'] for p in pages), default=0), flush=True)
                segments = client.get_transcript_segments(sid)
                print('SOURCE TRANSCRIPT', len(segments), 'characters', sum(len(s.get('text', '')) for s in segments), flush=True)
