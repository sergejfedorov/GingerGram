package org.telegram.tgnet;

public interface RequestTimeDelegate {
    void run(long time, String diagnostic);
}
