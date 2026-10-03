from beawake.lang import OTHER, reply_language


def test_languages():
    assert reply_language("Hey, are we still on for lunch on Saturday?") == "English"
    assert reply_language("شو رأيك نطلع السبت؟") == "Arabic"
    assert reply_language("Yarin aksam yemege gelir misin?") == OTHER
