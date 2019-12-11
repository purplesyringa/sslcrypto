import threading


def parallelize(cnt):
    def decorator(f):
        def decorated(*args, **kwargs):
            threads = []
            exception = None

            def run():
                try:
                    f(*args, **kwargs)
                except BaseException as e:
                    exception = e

            for _ in range(cnt):
                thread = threading.Thread(target=run)
                thread.daemon = True
                thread.start()
                threads.append(thread)
            for thread in threads:
                thread.join()

            if exception is not None:
                raise exception

        decorated.__name__ = f.__name__
        return decorated

    return decorator
