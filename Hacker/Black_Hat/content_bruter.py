import urllib.request as urllib2
import threading
import queue
import urllib

threads = 50
target_url = "http://testphp.vulnweb.com"
wordlist_file = "all.txt"
resume = None
user_agent = "Mozilla/5.0 (X11; Linux x86_64; rv:19.0) Gecko/20160711-Firefox/19.0"

def build_wordlist(wordlist_file):
        fd = open(wordlist_file, "r")
        raw_words = fd.readlines()
        fd.close()

        found_resume = False
        words = queue.Queue()

        for word in raw_words:
                word = word.rstrip()

                if resume is not None:
                        if found_resume:
                                words.put(word)
                        else:
                                if word == resume:
                                        found_resume = True
                                        print("Resuming wordlist from: %s" % resume)
                else:
                        words.put(word)

        return words

def dir_bruter(word_queue, extensions = None):
        while not word_queue.empty():
                attempt = word_queue.get()
                attempt_list = []

                if "." not in attempt:
                        attempt_list.append(attempt)
                else:
                        attempt_list.append("/%s" % attempt)

                if extensions:
                        for extension in extensions:
                                attempt_list.append("/%s%s" % (attempt, extension))

                for brute in attempt_list:
                        url = "%s%s" % (target_url, urllib.parse.quote(brute))

                        try:
                                headers = {}
                                headers["User-Agent"] = user_agent
                                r = urllib2.Request(url,headers = headers)
                                response = urllib2.urlopen(r)

                                if len(response.read()):
                                        print("[%d] => %s" % (response.code,url))
                        except urllib2.URLError as e:
                                if hasattr(e, 'code') and e.code != 404:
                                        print("!!! %d => %s" % (e.code,url))
                                pass

word_queue = build_wordlist(wordlist_file)

for i in range(threads):
        t = threading.Thread(target=dir_bruter, args=(word_queue, ))
        t.start()
