import threading


def parallelize(cnt):
    def decorator(f):
        def decorated(*args, **kwargs):
            def run():
                f(*args, **kwargs)

            threads = []
            for _ in range(cnt):
                thread = threading.Thread(target=run)
                thread.daemon = True
                thread.start()
                threads.append(thread)
            for thread in threads:
                thread.join()

        decorated.__name__ = f.__name__
        return decorated

    return decorator
