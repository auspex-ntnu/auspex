import main
from hypothesis import given, strategies as st


@given(st.builds(main.ImageInfo))
def test_imageinfo(info: main.ImageInfo) -> None:
    # TODO: add better tests
    assert info.image_size_bytes is not None
    assert info.layer_id is not None
    assert info.mediaType is not None
    assert info.tag is not None
    assert info.created is not None
    assert info.uploaded is not None
    if info.digest is not None:
        assert isinstance(info.digest, str)
    if info.image is not None:
        assert isinstance(info.image, str)


@given(st.builds(main.Scan))
def test_scan(scan: main.Scan) -> None:
    assert scan.image is not None
    assert isinstance(scan.image, main.ImageInfo)
    assert scan.backend is not None
    assert len(scan.backend) >= 1
    if scan.url is not None:
        assert isinstance(scan.url, str)
        assert any(scan.url.startswith(pfix) for pfix in ["http://", "https://"])
