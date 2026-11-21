package com.lamonlind.appscan;

import android.os.Handler;
import android.os.Looper;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

final class ScanController {
    interface Callback {
        void onProgress(long done, long total, long sent, long responded,
                        long failed, long skipped, double requestsPerSecond);
        void onHit(String method, int code, String server, int port, String host, String location);
        void onFinished(List<String> passedHosts);
        void onError(String message);
    }

    private static final int CONNECT_TIMEOUT_MS = 1000;
    private static final int READ_TIMEOUT_MS = 1000;

    private final Callback callback;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private volatile ExecutorService executor;
    private final AtomicBoolean stopping = new AtomicBoolean(false);
    private final AtomicBoolean finished = new AtomicBoolean(false);
    private final AtomicLong done = new AtomicLong();
    private final AtomicLong sent = new AtomicLong();
    private final AtomicLong responded = new AtomicLong();
    private final AtomicLong failed = new AtomicLong();
    private final AtomicLong skipped = new AtomicLong();
    private final Set<String> passedHosts = java.util.Collections.synchronizedSet(new LinkedHashSet<String>());
    private volatile long total;
    private volatile long startedAtNanos;
    private volatile Thread producerThread;
    private final Runnable progressTicker = new Runnable() {
        @Override
        public void run() {
            postProgress();
            if (!finished.get()) mainHandler.postDelayed(this, 500);
        }
    };

    ScanController(Callback callback) {
        this.callback = callback;
    }

    void start(final List<String> hosts, final List<Integer> ports, final int threads,
               final Ipv4Cidr cidr, final long hostCount) {
        stopping.set(false);
        finished.set(false);
        done.set(0);
        sent.set(0);
        responded.set(0);
        failed.set(0);
        skipped.set(0);
        passedHosts.clear();
        total = cidr != null ? hostCount * ports.size() : (long) hosts.size() * ports.size();
        startedAtNanos = System.nanoTime();
        postProgress();

        executor = Executors.newFixedThreadPool(threads);
        mainHandler.post(progressTicker);
        producerThread = new Thread(new Runnable() {
            @Override
            public void run() {
                if (cidr != null) {
                    submitCidr(cidr, ports);
                } else {
                    submitHosts(hosts, ports);
                }
                ExecutorService current = executor;
                if (current != null) current.shutdown();
                try {
                    if (current != null) current.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
                } catch (InterruptedException ignored) {
                    if (current != null) current.shutdownNow();
                }
                finish();
            }
        }, "appscan-producer");
        producerThread.start();
    }

    private void submitHosts(List<String> hosts, List<Integer> ports) {
        for (String host : hosts) {
            if (stopping.get()) break;
            host = host.trim();
            if (host.isEmpty()) continue;
            for (Integer port : ports) {
                if (stopping.get()) break;
                submitTask(host, port);
            }
        }
    }

    private void submitCidr(Ipv4Cidr cidr, List<Integer> ports) {
        for (long i = 0; i < cidr.count && !stopping.get(); i++) {
            String host = Ipv4Cidr.format(cidr.first + i);
            for (Integer port : ports) {
                if (stopping.get()) break;
                submitTask(host, port);
            }
        }
    }

    private void submitTask(final String host, final int port) {
        try {
            executor.execute(new Runnable() {
                @Override
                public void run() {
                    check(host, port);
                }
            });
        } catch (RejectedExecutionException e) {
            skipped.incrementAndGet();
            incrementDone();
        }
    }

    private void check(String host, int port) {
        if (stopping.get()) {
            skipped.incrementAndGet();
            incrementDone();
            return;
        }

        HttpURLConnection connection = null;
        int code = 0;
        String server = "";
        String location = "";
        boolean gotResponse = false;

        for (int attempt = 0; attempt < 2; attempt++) {
            if (stopping.get()) {
                skipped.incrementAndGet();
                incrementDone();
                return;
            }
            sent.incrementAndGet();
            try {
                String urlText = "http://" + (omitPort(port) ? host : host + ":" + port);
                URL url = new URL(urlText);
                connection = (HttpURLConnection) url.openConnection();
                connection.setInstanceFollowRedirects(false);
                connection.setRequestMethod("HEAD");
                connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
                connection.setReadTimeout(READ_TIMEOUT_MS);
                connection.setUseCaches(false);
                code = connection.getResponseCode();
                server = header(connection, "Server");
                location = header(connection, "Location");
                responded.incrementAndGet();
                gotResponse = true;
                break;
            } catch (Exception ignored) {
                code = 0;
            } finally {
                if (connection != null) connection.disconnect();
            }
        }

        if (!gotResponse) {
            if (stopping.get()) {
                skipped.incrementAndGet();
            } else {
                failed.incrementAndGet();
            }
        } else if (!stopping.get()) {
            if (code >= 100 &&
                    !"https://jio.com/BalanceExhaust".equals(location) &&
                    !"AkamaiGHost".equals(server) &&
                    !"AkamaiNetStorage".equals(server)) {
                passedHosts.add(host);
                postHit("HEAD", code, server, port, host, location);
            }
        }
        incrementDone();
    }

    private boolean omitPort(int port) {
        return port == 80;
    }

    private String header(HttpURLConnection connection, String name) {
        String value = connection.getHeaderField(name);
        return value == null ? "" : value;
    }

    private void incrementDone() {
        long value = done.incrementAndGet();
        if (value % 100 == 0 || value == total) postProgress();
    }

    private void postProgress() {
        final long value = done.get();
        final long sentValue = sent.get();
        final long respondedValue = responded.get();
        final long failedValue = failed.get();
        final long skippedValue = skipped.get();
        final long elapsedMillis = Math.max(1L, (System.nanoTime() - startedAtNanos) / 1000000L);
        final double rps = sentValue * 1000.0 / elapsedMillis;
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                callback.onProgress(value, total, sentValue, respondedValue,
                        failedValue, skippedValue, rps);
            }
        });
    }

    private void postHit(final String method, final int code, final String server,
                         final int port, final String host, final String location) {
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                callback.onHit(method, code, server, port, host, location);
            }
        });
    }

    private void finish() {
        if (!finished.compareAndSet(false, true)) return;
        long remaining = total - done.get();
        if (remaining > 0) {
            skipped.addAndGet(remaining);
            done.addAndGet(remaining);
        }
        if (done.get() > total) done.set(total);
        mainHandler.removeCallbacks(progressTicker);
        postProgress();
        final ArrayList<String> hosts = new ArrayList<String>(passedHosts);
        mainHandler.post(new Runnable() {
            @Override
            public void run() {
                callback.onFinished(hosts);
            }
        });
    }

    void stop() {
        if (!stopping.compareAndSet(false, true)) return;
        ExecutorService current = executor;
        if (current != null) {
            List<Runnable> canceled = current.shutdownNow();
            for (Runnable ignored : canceled) {
                skipped.incrementAndGet();
                incrementDone();
            }
        }
        Thread producer = producerThread;
        if (producer != null) producer.interrupt();
    }
}
