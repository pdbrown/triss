import pytest

from triss.byte_seqs import take_and_drop, resize_seqs

def test_take_and_drop():
    bs = [b'asdf', b'qwer', b'zxcv']
    head, bs = take_and_drop(0, bs)
    assert head == b''
    head, bs = take_and_drop(1, bs)
    assert head == b'a'
    head, bs = take_and_drop(2, bs)
    assert head == b'sd'
    head, bs = take_and_drop(1, bs)
    assert head == b'f'

    head, bs = take_and_drop(1, bs)
    assert head == b'q'
    head, bs = take_and_drop(4, bs)
    assert head == b'werz'
    head, bs = take_and_drop(4, bs)
    assert head == b'xcv'

    with pytest.raises(StopIteration):
        take_and_drop(1, bs)

def test_resize_seqs():
    assert list(resize_seqs(1024, [])) == []
    assert list(resize_seqs(1024, [b''])) == []
    assert list(resize_seqs(1, [b'aaa'])) == [b'a', b'a', b'a']
    assert list(resize_seqs(3, [
        b'asdf',
        b'',
        b'qw',
        b'erzx',
        b''])) == [b'asd', b'fqw', b'erz', b'x']
    assert list(resize_seqs(100, [b'as', b'dfqw'])) == [b'asdfqw']
