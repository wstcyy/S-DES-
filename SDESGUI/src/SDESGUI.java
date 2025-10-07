import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * S-DES加密解密工具图形界面
 * 实现S-DES算法的加密、解密、ASCII加解密和暴力破解功能
 */
public class SDESGUI extends JFrame {

    // ==================== S-DES算法常量定义 ====================

    // 密钥扩展置换盒
    private static final int[] P10 = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};
    private static final int[] P8 = {6, 3, 7, 4, 8, 5, 10, 9};

    // 初始置换和最终置换
    private static final int[] IP = {2, 6, 3, 1, 4, 8, 5, 7};
    private static final int[] IP_INV = {4, 1, 3, 5, 7, 2, 8, 6};

    // 轮函数相关置换盒
    private static final int[] EP = {4, 1, 2, 3, 2, 3, 4, 1};
    private static final int[] P4 = {2, 4, 3, 1};

    // S盒定义
    private static final int[][] SBOX1 = {
            {1, 0, 3, 2},
            {3, 2, 1, 0},
            {0, 2, 1, 3},
            {3, 1, 0, 2}
    };

    private static final int[][] SBOX2 = {
            {0, 1, 2, 3},
            {2, 3, 1, 0},
            {3, 0, 1, 2},
            {2, 1, 0, 3}
    };

    // ==================== GUI组件定义 ====================

    private JTextField plainTextField;
    private JTextField keyTextField;
    private JTextField cipherTextField;
    private JTextArea resultArea;
    private JButton encryptButton;
    private JButton decryptButton;
    private JButton asciiEncryptButton;
    private JButton asciiDecryptButton;
    private JButton bruteForceButton;
    private JButton analysisButton;

    /**
     * 构造函数，初始化GUI界面
     */
    public SDESGUI() {
        initializeGUI();
    }

    /**
     * 初始化图形用户界面
     */
    private void initializeGUI() {
        setTitle("S-DES加密解密工具 - 符合标准算法");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        // 设置中文字体
        setUIFont(new Font("Microsoft YaHei", Font.PLAIN, 12));

        // 创建输入面板
        JPanel inputPanel = createInputPanel();

        // 创建结果显示区域
        resultArea = new JTextArea(15, 60);
        resultArea.setEditable(false);
        resultArea.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        JScrollPane scrollPane = new JScrollPane(resultArea);

        // 添加组件到主窗口
        add(inputPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);

        // 添加事件监听器
        addEventListeners();

        pack();
        setLocationRelativeTo(null);
        setVisible(true);
    }

    /**
     * 设置UI字体（解决中文乱码问题）
     */
    private void setUIFont(Font font) {
        java.util.Enumeration<Object> keys = UIManager.getDefaults().keys();
        while (keys.hasMoreElements()) {
            Object key = keys.nextElement();
            Object value = UIManager.get(key);
            if (value instanceof Font) {
                UIManager.put(key, font);
            }
        }
    }

    /**
     * 创建输入面板
     */
    private JPanel createInputPanel() {
        JPanel inputPanel = new JPanel(new GridLayout(5, 2, 5, 5));
        inputPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // 明文输入
        JLabel plainLabel = new JLabel("明文(8位二进制):");
        plainLabel.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        inputPanel.add(plainLabel);
        plainTextField = new JTextField();
        plainTextField.setToolTipText("请输入8位二进制数，如：10101010");
        inputPanel.add(plainTextField);

        // 密钥输入
        JLabel keyLabel = new JLabel("密钥(10位二进制):");
        keyLabel.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        inputPanel.add(keyLabel);
        keyTextField = new JTextField();
        keyTextField.setToolTipText("请输入10位二进制数，如：1010101010");
        inputPanel.add(keyTextField);

        // 密文输入
        JLabel cipherLabel = new JLabel("密文(8位二进制):");
        cipherLabel.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        inputPanel.add(cipherLabel);
        cipherTextField = new JTextField();
        cipherTextField.setToolTipText("显示或输入8位二进制密文");
        inputPanel.add(cipherTextField);

        // 操作按钮标签
        JLabel operationLabel = new JLabel("操作按钮:");
        operationLabel.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        inputPanel.add(operationLabel);
        JPanel buttonPanel = createButtonPanel();
        inputPanel.add(buttonPanel);

        // 测试数据标签
        JLabel testLabel = new JLabel("测试数据:");
        testLabel.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        inputPanel.add(testLabel);
        JPanel testPanel = createTestPanel();
        inputPanel.add(testPanel);

        return inputPanel;
    }

    /**
     * 创建按钮面板
     */
    private JPanel createButtonPanel() {
        JPanel buttonPanel = new JPanel(new FlowLayout());

        encryptButton = createChineseButton("加密");
        decryptButton = createChineseButton("解密");
        asciiEncryptButton = createChineseButton("ASCII加密");
        asciiDecryptButton = createChineseButton("ASCII解密");
        bruteForceButton = createChineseButton("暴力破解");
        analysisButton = createChineseButton("算法分析");

        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);
        buttonPanel.add(asciiEncryptButton);
        buttonPanel.add(asciiDecryptButton);
        buttonPanel.add(bruteForceButton);
        buttonPanel.add(analysisButton);

        return buttonPanel;
    }

    /**
     * 创建支持中文的按钮
     */
    private JButton createChineseButton(String text) {
        JButton button = new JButton(text);
        button.setFont(new Font("Microsoft YaHei", Font.PLAIN, 12));
        return button;
    }

    /**
     * 创建测试数据面板
     */
    private JPanel createTestPanel() {
        JPanel testPanel = new JPanel(new FlowLayout());

        JButton test1Button = createChineseButton("测试1");
        JButton test2Button = createChineseButton("测试2");
        JButton clearButton = createChineseButton("清空");

        test1Button.addActionListener(e -> {
            plainTextField.setText("00001111");
            keyTextField.setText("1010101010");
            resultArea.append("已加载测试数据1: 明文=00001111, 密钥=1010101010\n");
        });

        test2Button.addActionListener(e -> {
            plainTextField.setText("11110000");
            keyTextField.setText("0101010101");
            resultArea.append("已加载测试数据2: 明文=11110000, 密钥=0101010101\n");
        });

        clearButton.addActionListener(e -> {
            plainTextField.setText("");
            cipherTextField.setText("");
            resultArea.setText("");
        });

        testPanel.add(test1Button);
        testPanel.add(test2Button);
        testPanel.add(clearButton);

        return testPanel;
    }

    /**
     * 添加事件监听器
     */
    private void addEventListeners() {
        encryptButton.addActionListener(e -> performEncryption());
        decryptButton.addActionListener(e -> performDecryption());
        asciiEncryptButton.addActionListener(e -> performAsciiEncryption());
        asciiDecryptButton.addActionListener(e -> performAsciiDecryption());
        bruteForceButton.addActionListener(e -> performBruteForce());
        analysisButton.addActionListener(e -> performAlgorithmAnalysis());
    }

    // ==================== S-DES核心算法实现 ====================

    /**
     * 置换函数
     * @param input 输入位数组
     * @param pattern 置换模式
     * @return 置换后的位数组
     */
    private int[] permute(int[] input, int[] pattern) {
        int[] output = new int[pattern.length];
        for (int i = 0; i < pattern.length; i++) {
            output[i] = input[pattern[i] - 1];
        }
        return output;
    }

    /**
     * 左循环移位函数
     * @param input 输入位数组
     * @param shifts 移位位数
     * @return 移位后的位数组
     */
    private int[] leftShift(int[] input, int shifts) {
        int[] output = new int[input.length];
        System.arraycopy(input, shifts, output, 0, input.length - shifts);
        System.arraycopy(input, 0, output, input.length - shifts, shifts);
        return output;
    }

    /**
     * 生成子密钥
     * @param key 原始10位密钥
     * @return 包含两个8位子密钥的数组 [k1, k2]
     */
    private int[][] generateSubKeys(int[] key) {
        // P10置换
        int[] p10Result = permute(key, P10);

        // 分割成左右两部分各5位
        int[] leftHalf = new int[5];
        int[] rightHalf = new int[5];
        System.arraycopy(p10Result, 0, leftHalf, 0, 5);
        System.arraycopy(p10Result, 5, rightHalf, 0, 5);

        // 生成子密钥k1 (左移1位)
        int[] leftShift1 = leftShift(leftHalf, 1);
        int[] rightShift1 = leftShift(rightHalf, 1);
        int[] combined1 = new int[10];
        System.arraycopy(leftShift1, 0, combined1, 0, 5);
        System.arraycopy(rightShift1, 0, combined1, 5, 5);
        int[] subKey1 = permute(combined1, P8);

        // 生成子密钥k2 (左移2位)
        int[] leftShift2 = leftShift(leftShift1, 2);
        int[] rightShift2 = leftShift(rightShift1, 2);
        int[] combined2 = new int[10];
        System.arraycopy(leftShift2, 0, combined2, 0, 5);
        System.arraycopy(rightShift2, 0, combined2, 5, 5);
        int[] subKey2 = permute(combined2, P8);

        return new int[][]{subKey1, subKey2};
    }

    /**
     * S盒处理函数
     * @param input 4位输入
     * @param sbox S盒
     * @return 2位输出
     */
    private int[] sBoxOperation(int[] input, int[][] sbox) {
        int row = input[0] * 2 + input[3];  // 第1位和第4位决定行
        int col = input[1] * 2 + input[2];  // 第2位和第3位决定列
        int value = sbox[row][col];
        // 将数值转换为2位二进制
        return new int[]{(value >> 1) & 1, value & 1};
    }

    /**
     * F轮函数
     * @param rightHalf 右半部分4位输入
     * @param subKey 8位子密钥
     * @return 4位输出
     */
    private int[] fFunction(int[] rightHalf, int[] subKey) {
        // 扩展置换EP (4位到8位)
        int[] expanded = permute(rightHalf, EP);

        // 与子密钥异或
        int[] xorResult = new int[8];
        for (int i = 0; i < 8; i++) {
            xorResult[i] = expanded[i] ^ subKey[i];
        }

        // S盒处理
        int[] leftPart = new int[]{xorResult[0], xorResult[1], xorResult[2], xorResult[3]};
        int[] rightPart = new int[]{xorResult[4], xorResult[5], xorResult[6], xorResult[7]};

        int[] sbox1Output = sBoxOperation(leftPart, SBOX1);
        int[] sbox2Output = sBoxOperation(rightPart, SBOX2);

        // 合并S盒输出
        int[] combined = new int[4];
        System.arraycopy(sbox1Output, 0, combined, 0, 2);
        System.arraycopy(sbox2Output, 0, combined, 2, 2);

        // P4置换
        return permute(combined, P4);
    }

    /**
     * 加密单个8位分组
     * @param plaintext 8位明文
     * @param key 10位密钥
     * @return 8位密文
     */
    public int[] encryptBlock(int[] plaintext, int[] key) {
        int[][] subKeys = generateSubKeys(key);
        return processBlock(plaintext, subKeys[0], subKeys[1]);
    }

    /**
     * 解密单个8位分组
     * @param ciphertext 8位密文
     * @param key 10位密钥
     * @return 8位明文
     */
    public int[] decryptBlock(int[] ciphertext, int[] key) {
        int[][] subKeys = generateSubKeys(key);
        // 解密时使用子密钥的顺序与加密相反
        return processBlock(ciphertext, subKeys[1], subKeys[0]);
    }

    /**
     * 处理数据分组 (加密/解密的通用流程)
     * @param block 8位数据分组
     * @param firstKey 第一轮子密钥
     * @param secondKey 第二轮子密钥
     * @return 处理后的8位数据
     */
    private int[] processBlock(int[] block, int[] firstKey, int[] secondKey) {
        // 初始置换IP
        int[] initialPermutation = permute(block, IP);

        // 分割成左右两部分各4位
        int[] leftHalf = new int[4];
        int[] rightHalf = new int[4];
        System.arraycopy(initialPermutation, 0, leftHalf, 0, 4);
        System.arraycopy(initialPermutation, 4, rightHalf, 0, 4);

        // ========== 第一轮 ==========
        int[] fResult1 = fFunction(rightHalf, firstKey);
        int[] newLeft1 = new int[4];
        for (int i = 0; i < 4; i++) {
            newLeft1[i] = leftHalf[i] ^ fResult1[i];
        }

        // 交换左右部分
        int[] temp = rightHalf;
        rightHalf = newLeft1;
        leftHalf = temp;

        // ========== 第二轮 ==========
        int[] fResult2 = fFunction(rightHalf, secondKey);
        int[] newLeft2 = new int[4];
        for (int i = 0; i < 4; i++) {
            newLeft2[i] = leftHalf[i] ^ fResult2[i];
        }

        // 合并左右部分
        int[] combined = new int[8];
        System.arraycopy(newLeft2, 0, combined, 0, 4);
        System.arraycopy(rightHalf, 0, combined, 4, 4);

        // 最终置换IP^{-1}
        return permute(combined, IP_INV);
    }

    // ==================== 工具函数 ====================

    /**
     * 二进制字符串转位数组
     */
    private int[] binaryStringToArray(String binaryString) {
        int[] result = new int[binaryString.length()];
        for (int i = 0; i < binaryString.length(); i++) {
            char c = binaryString.charAt(i);
            if (c != '0' && c != '1') {
                throw new IllegalArgumentException("输入必须为二进制字符串");
            }
            result[i] = Character.getNumericValue(c);
        }
        return result;
    }

    /**
     * 位数组转二进制字符串
     */
    private String arrayToBinaryString(int[] array) {
        StringBuilder sb = new StringBuilder();
        for (int bit : array) {
            sb.append(bit);
        }
        return sb.toString();
    }

    /**
     * ASCII字符串转二进制数组
     */
    private int[][] asciiToBinaryArrays(String text) {
        int[][] result = new int[text.length()][8];
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            String binary = String.format("%8s", Integer.toBinaryString(c & 0xFF)).replace(' ', '0');
            for (int j = 0; j < 8; j++) {
                result[i][j] = Character.getNumericValue(binary.charAt(j));
            }
        }
        return result;
    }

    /**
     * 二进制数组转ASCII字符串（改进版本，处理乱码问题）
     */
    private String binaryArraysToAscii(int[][] arrays) {
        StringBuilder sb = new StringBuilder();
        for (int[] array : arrays) {
            int value = 0;
            for (int i = 0; i < 8; i++) {
                value = (value << 1) | array[i];
            }
            // 只显示可打印ASCII字符（32-126），其他显示为转义形式
            if (value >= 32 && value <= 126) {
                sb.append((char) value);
            } else {
                sb.append(String.format("\\x%02X", value));
            }
        }
        return sb.toString();
    }

    /**
     * 二进制数组转十六进制字符串（用于显示加密结果）
     */
    private String binaryArraysToHex(int[][] arrays) {
        StringBuilder sb = new StringBuilder();
        for (int[] array : arrays) {
            int value = 0;
            for (int i = 0; i < 8; i++) {
                value = (value << 1) | array[i];
            }
            sb.append(String.format("%02X ", value));
        }
        return sb.toString().trim();
    }

    /**
     * 十六进制字符串转二进制数组
     */
    private int[][] hexToBinaryArrays(String hexText) {
        String[] hexBytes = hexText.split("\\s+");
        int[][] result = new int[hexBytes.length][8];

        for (int i = 0; i < hexBytes.length; i++) {
            int value = Integer.parseInt(hexBytes[i], 16);
            String binary = String.format("%8s", Integer.toBinaryString(value & 0xFF)).replace(' ', '0');
            for (int j = 0; j < 8; j++) {
                result[i][j] = Character.getNumericValue(binary.charAt(j));
            }
        }
        return result;
    }

    /**
     * 验证二进制输入
     */
    private boolean validateBinaryInput(String input, int expectedLength) {
        if (input.length() != expectedLength) {
            return false;
        }
        for (char c : input.toCharArray()) {
            if (c != '0' && c != '1') {
                return false;
            }
        }
        return true;
    }

    // ==================== GUI操作处理 ====================

    /**
     * 执行加密操作
     */
    private void performEncryption() {
        try {
            String plainText = plainTextField.getText().trim();
            String keyText = keyTextField.getText().trim();

            if (!validateBinaryInput(plainText, 8)) {
                JOptionPane.showMessageDialog(this, "明文必须为8位二进制数 (0和1组成)");
                return;
            }
            if (!validateBinaryInput(keyText, 10)) {
                JOptionPane.showMessageDialog(this, "密钥必须为10位二进制数 (0和1组成)");
                return;
            }

            int[] plaintext = binaryStringToArray(plainText);
            int[] key = binaryStringToArray(keyText);

            int[] ciphertext = encryptBlock(plaintext, key);
            String cipherTextStr = arrayToBinaryString(ciphertext);

            cipherTextField.setText(cipherTextStr);
            resultArea.append(String.format("加密: 明文=%s, 密钥=%s -> 密文=%s\n",
                    plainText, keyText, cipherTextStr));

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "加密错误: " + ex.getMessage());
        }
    }

    /**
     * 执行解密操作
     */
    private void performDecryption() {
        try {
            String cipherText = cipherTextField.getText().trim();
            String keyText = keyTextField.getText().trim();

            if (!validateBinaryInput(cipherText, 8)) {
                JOptionPane.showMessageDialog(this, "密文必须为8位二进制数 (0和1组成)");
                return;
            }
            if (!validateBinaryInput(keyText, 10)) {
                JOptionPane.showMessageDialog(this, "密钥必须为10位二进制数 (0和1组成)");
                return;
            }

            int[] ciphertext = binaryStringToArray(cipherText);
            int[] key = binaryStringToArray(keyText);

            int[] plaintext = decryptBlock(ciphertext, key);
            String plainTextStr = arrayToBinaryString(plaintext);

            plainTextField.setText(plainTextStr);
            resultArea.append(String.format("解密: 密文=%s, 密钥=%s -> 明文=%s\n",
                    cipherText, keyText, plainTextStr));

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "解密错误: " + ex.getMessage());
        }
    }

    /**
     * 执行ASCII加密
     */
    private void performAsciiEncryption() {
        try {
            String plainText = JOptionPane.showInputDialog(this, "请输入要加密的ASCII文本:");
            if (plainText == null || plainText.isEmpty()) return;

            String keyText = keyTextField.getText().trim();
            if (!validateBinaryInput(keyText, 10)) {
                JOptionPane.showMessageDialog(this, "密钥必须为10位二进制数");
                return;
            }

            int[] key = binaryStringToArray(keyText);
            int[][] plaintextBlocks = asciiToBinaryArrays(plainText);
            int[][] ciphertextBlocks = new int[plaintextBlocks.length][8];

            for (int i = 0; i < plaintextBlocks.length; i++) {
                ciphertextBlocks[i] = encryptBlock(plaintextBlocks[i], key);
            }

            String cipherTextAscii = binaryArraysToAscii(ciphertextBlocks);
            String cipherTextHex = binaryArraysToHex(ciphertextBlocks);

            resultArea.append(String.format("ASCII加密: '%s' -> '%s'\n", plainText, cipherTextAscii));
            resultArea.append(String.format("十六进制: %s\n", cipherTextHex));
            resultArea.append(String.format("原始二进制: "));
            for (int[] block : ciphertextBlocks) {
                resultArea.append(arrayToBinaryString(block) + " ");
            }
            resultArea.append("\n");

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "ASCII加密错误: " + ex.getMessage());
        }
    }

    /**
     * 执行ASCII解密
     */
    private void performAsciiDecryption() {
        try {
            // 提供两种输入方式：直接输入加密文本或输入十六进制
            Object[] options = {"输入加密文本", "输入十六进制"};
            int choice = JOptionPane.showOptionDialog(this,
                    "请选择输入方式：\n- 加密文本：直接输入加密后的文本（可能包含乱码）\n- 十六进制：输入十六进制格式的密文",
                    "ASCII解密",
                    JOptionPane.DEFAULT_OPTION,
                    JOptionPane.QUESTION_MESSAGE,
                    null,
                    options,
                    options[0]);

            if (choice == -1) return; // 用户取消

            String cipherText;
            int[][] ciphertextBlocks;

            if (choice == 0) {
                // 直接输入加密文本
                cipherText = JOptionPane.showInputDialog(this, "请输入要解密的ASCII文本:");
                if (cipherText == null || cipherText.isEmpty()) return;
                ciphertextBlocks = asciiToBinaryArrays(cipherText);
            } else {
                // 输入十六进制
                cipherText = JOptionPane.showInputDialog(this, "请输入十六进制密文（用空格分隔）:");
                if (cipherText == null || cipherText.isEmpty()) return;
                ciphertextBlocks = hexToBinaryArrays(cipherText);
            }

            String keyText = keyTextField.getText().trim();
            if (!validateBinaryInput(keyText, 10)) {
                JOptionPane.showMessageDialog(this, "密钥必须为10位二进制数");
                return;
            }

            int[] key = binaryStringToArray(keyText);
            int[][] plaintextBlocks = new int[ciphertextBlocks.length][8];

            for (int i = 0; i < ciphertextBlocks.length; i++) {
                plaintextBlocks[i] = decryptBlock(ciphertextBlocks[i], key);
            }

            String plainTextAscii = binaryArraysToAscii(plaintextBlocks);
            resultArea.append(String.format("ASCII解密: 输入长度=%d -> '%s'\n",
                    ciphertextBlocks.length, plainTextAscii));

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "ASCII解密错误: " + ex.getMessage());
        }
    }

    /**
     * 执行暴力破解 - 修复版本
     */
    private void performBruteForce() {
        try {
            String plainText = JOptionPane.showInputDialog(this, "请输入已知明文(8位二进制):");
            String cipherText = JOptionPane.showInputDialog(this, "请输入对应密文(8位二进制):");

            if (plainText == null || cipherText == null ||
                    !validateBinaryInput(plainText, 8) || !validateBinaryInput(cipherText, 8)) {
                JOptionPane.showMessageDialog(this, "明文和密文必须为8位二进制数");
                return;
            }

            int[] plaintext = binaryStringToArray(plainText);
            int[] ciphertext = binaryStringToArray(cipherText);

            resultArea.append("开始暴力破解...\n");
            resultArea.append(String.format("已知: 明文=%s, 密文=%s\n", plainText, cipherText));
            long startTime = System.currentTimeMillis();

            AtomicBoolean found = new AtomicBoolean(false);
            int threadCount = Runtime.getRuntime().availableProcessors();
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);

            resultArea.append("使用 " + threadCount + " 个线程进行破解...\n");

            // 遍历所有可能的1024个密钥 - 修复版本
            for (int keyValue = 0; keyValue < 1024; keyValue++) {
                if (found.get()) break;

                final int currentKey = keyValue;
                executor.execute(() -> {
                    if (found.get()) return;

                    try {
                        // 确保密钥格式正确为10位
                        String keyBinary = String.format("%10s", Integer.toBinaryString(currentKey))
                                .replace(' ', '0');

                        // 验证密钥长度
                        if (keyBinary.length() != 10) {
                            return;
                        }

                        int[] key = binaryStringToArray(keyBinary);

                        // 使用相同的加密算法进行验证
                        int[] testCiphertext = encryptBlock(plaintext, key);

                        // 比较密文是否匹配
                        if (java.util.Arrays.equals(testCiphertext, ciphertext)) {
                            if (found.compareAndSet(false, true)) {
                                long endTime = System.currentTimeMillis();
                                long duration = endTime - startTime;

                                SwingUtilities.invokeLater(() -> {
                                    resultArea.append(">>> 找到密钥: " + keyBinary + " (十进制: " + currentKey + ")\n");
                                    resultArea.append(">>> 破解耗时: " + duration + "ms\n");
                                    keyTextField.setText(keyBinary);

                                    // 验证找到的密钥
                                    int[] decrypted = decryptBlock(ciphertext, key);
                                    String decryptedStr = arrayToBinaryString(decrypted);
                                    resultArea.append(">>> 验证: 使用该密钥解密得到: " + decryptedStr + "\n");

                                    // 显示加密验证
                                    int[] encryptedAgain = encryptBlock(plaintext, key);
                                    String encryptedStr = arrayToBinaryString(encryptedAgain);
                                    resultArea.append(">>> 验证: 使用该密钥加密得到: " + encryptedStr + "\n");

                                    if (plainText.equals(decryptedStr) && cipherText.equals(encryptedStr)) {
                                        resultArea.append(">>> 验证成功: 密钥完全正确！\n");
                                    } else {
                                        resultArea.append(">>> 警告: 密钥验证不一致！\n");
                                    }
                                });
                            }
                        }
                    } catch (Exception e) {
                        // 忽略单个密钥的错误，继续尝试其他密钥
                    }
                });
            }

            executor.shutdown();

            // 监控线程，检查破解状态
            new Thread(() -> {
                try {
                    // 等待所有任务完成
                    executor.awaitTermination(1, java.util.concurrent.TimeUnit.MINUTES);

                    if (!found.get()) {
                        SwingUtilities.invokeLater(() -> {
                            resultArea.append(">>> 未找到匹配的密钥\n");
                            resultArea.append(">>> 可能的原因:\n");
                            resultArea.append(">>> 1. 输入的明文/密文不正确\n");
                            resultArea.append(">>> 2. 存在密钥碰撞（多个密钥产生相同密文）\n");
                            resultArea.append(">>> 3. 算法实现可能存在差异\n");
                        });
                    }
                } catch (InterruptedException ex) {
                    SwingUtilities.invokeLater(() -> {
                        resultArea.append(">>> 破解过程被中断\n");
                    });
                }
            }).start();

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "暴力破解错误: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

    /**
     * 执行算法分析
     */
    private void performAlgorithmAnalysis() {
        resultArea.append("\n=== S-DES算法分析 ===\n");

        // 测试密钥碰撞
        resultArea.append("1. 密钥碰撞测试:\n");
        testKeyCollisions();

        // 测试加解密一致性
        resultArea.append("2. 加解密一致性测试:\n");
        testEncryptDecryptConsistency();

        // 交叉测试验证
        resultArea.append("3. 交叉测试验证:\n");
        testCrossPlatformCompatibility();
    }

    /**
     * 测试密钥碰撞
     */
    private void testKeyCollisions() {
        int collisionCount = 0;
        String testPlaintext = "10101010";
        int[] plaintext = binaryStringToArray(testPlaintext);

        // 测试前100个密钥
        for (int i = 0; i < 100; i++) {
            String key1 = String.format("%10s", Integer.toBinaryString(i)).replace(' ', '0');
            int[] cipher1 = encryptBlock(plaintext, binaryStringToArray(key1));

            for (int j = i + 1; j < 100; j++) {
                String key2 = String.format("%10s", Integer.toBinaryString(j)).replace(' ', '0');
                int[] cipher2 = encryptBlock(plaintext, binaryStringToArray(key2));

                if (java.util.Arrays.equals(cipher1, cipher2)) {
                    collisionCount++;
                    resultArea.append(String.format("   密钥碰撞: K%s 和 K%s 产生相同密文\n", key1, key2));
                }
            }
        }

        resultArea.append(String.format("   在前100个密钥中发现 %d 次碰撞\n", collisionCount));
    }

    /**
     * 测试加解密一致性
     */
    private void testEncryptDecryptConsistency() {
        int successCount = 0;
        int totalTests = 50;

        for (int i = 0; i < totalTests; i++) {
            String plaintext = String.format("%8s", Integer.toBinaryString(i)).replace(' ', '0');
            String key = String.format("%10s", Integer.toBinaryString(i * 20)).replace(' ', '0');

            try {
                int[] encrypted = encryptBlock(binaryStringToArray(plaintext), binaryStringToArray(key));
                int[] decrypted = decryptBlock(encrypted, binaryStringToArray(key));
                String decryptedStr = arrayToBinaryString(decrypted);

                if (plaintext.equals(decryptedStr)) {
                    successCount++;
                }
            } catch (Exception e) {
                // 忽略测试错误
            }
        }

        resultArea.append(String.format("   加解密一致性: %d/%d 测试通过\n", successCount, totalTests));
    }

    /**
     * 交叉测试验证
     */
    private void testCrossPlatformCompatibility() {
        resultArea.append("   使用标准测试向量验证:\n");

        // 标准测试向量
        String[][] testVectors = {
                {"00000000", "0000000000", "11101001"},  // 测试向量1
                {"11111111", "1111111111", "00001100"},  // 测试向量2
                {"10101010", "1010101010", "01110010"}   // 测试向量3
        };

        for (String[] vector : testVectors) {
            String plaintext = vector[0];
            String key = vector[1];
            String expectedCipher = vector[2];

            try {
                int[] cipher = encryptBlock(binaryStringToArray(plaintext), binaryStringToArray(key));
                String cipherStr = arrayToBinaryString(cipher);

                if (cipherStr.equals(expectedCipher)) {
                    resultArea.append(String.format("   ✓ 测试通过: %s + %s -> %s\n", plaintext, key, cipherStr));
                } else {
                    resultArea.append(String.format("   ✗ 测试失败: %s + %s -> %s (期望: %s)\n",
                            plaintext, key, cipherStr, expectedCipher));
                }
            } catch (Exception e) {
                resultArea.append(String.format("   ✗ 测试异常: %s\n", e.getMessage()));
            }
        }
    }

    // ==================== 主函数 ====================

    public static void main(String[] args) {
        // 设置系统外观和中文支持
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            // 设置默认字体支持中文
            System.setProperty("file.encoding", "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
        }

        SwingUtilities.invokeLater(() -> {
            new SDESGUI();
        });
    }
}