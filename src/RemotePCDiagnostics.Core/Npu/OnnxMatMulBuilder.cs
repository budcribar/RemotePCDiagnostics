using System.Text;

namespace RemotePCDiagnostics.Core.Npu;

/// <summary>
/// Builds a minimal, spec-compliant in-memory ONNX (IR v8, opset 17) model containing a single
/// <c>MatMul(A[N,N], B[N,N]) -&gt; C[N,N]</c> float32 node. Used by Windows ML / ONNX Runtime to run
/// a deterministic, CPU-verifiable workload on Qualcomm (QNN), AMD (VitisAI), and Intel (OpenVINO) NPUs
/// without bundling or downloading external model files.
/// </summary>
public static class OnnxMatMulBuilder
{
    private const long IrVersion = 8;
    private const long OpsetVersion = 17;
    private const int TensorDataTypeFloat = 1;

    public static byte[] BuildFloat32MatMul(int matrixSize)
    {
        if (matrixSize <= 0) throw new ArgumentOutOfRangeException(nameof(matrixSize));

        var node = EncodeMessage(w =>
        {
            WriteString(w, 1, "A");       // NodeProto.input
            WriteString(w, 1, "B");       // NodeProto.input
            WriteString(w, 2, "C");       // NodeProto.output
            WriteString(w, 4, "MatMul");  // NodeProto.op_type
        });

        var inputA = EncodeMatrixValueInfo("A", matrixSize);
        var inputB = EncodeMatrixValueInfo("B", matrixSize);
        var outputC = EncodeMatrixValueInfo("C", matrixSize);

        var graph = EncodeMessage(w =>
        {
            WriteBytes(w, 1, node);             // GraphProto.node
            WriteString(w, 2, "npu_matmul");    // GraphProto.name
            WriteBytes(w, 11, inputA);          // GraphProto.input
            WriteBytes(w, 11, inputB);          // GraphProto.input
            WriteBytes(w, 12, outputC);         // GraphProto.output
        });

        var opset = EncodeMessage(w =>
        {
            WriteString(w, 1, "");              // OperatorSetIdProto.domain (default ai.onnx)
            WriteVarintField(w, 2, OpsetVersion); // OperatorSetIdProto.version
        });

        return EncodeMessage(w =>
        {
            WriteVarintField(w, 1, IrVersion);  // ModelProto.ir_version
            WriteBytes(w, 7, graph);            // ModelProto.graph
            WriteBytes(w, 8, opset);            // ModelProto.opset_import
        });
    }

    private static byte[] EncodeMatrixValueInfo(string name, int n)
    {
        var dim = EncodeMessage(w => WriteVarintField(w, 1, n)); // TensorShapeProto.Dimension.dim_value
        var shape = EncodeMessage(w =>
        {
            WriteBytes(w, 1, dim);
            WriteBytes(w, 1, dim);
        });
        var tensorType = EncodeMessage(w =>
        {
            WriteVarintField(w, 1, TensorDataTypeFloat); // TypeProto.Tensor.elem_type = FLOAT
            WriteBytes(w, 2, shape);                     // TypeProto.Tensor.shape
        });
        var typeProto = EncodeMessage(w => WriteBytes(w, 1, tensorType)); // TypeProto.tensor_type
        return EncodeMessage(w =>
        {
            WriteString(w, 1, name);      // ValueInfoProto.name
            WriteBytes(w, 2, typeProto);  // ValueInfoProto.type
        });
    }

    private static byte[] EncodeMessage(Action<MemoryStream> write)
    {
        using var ms = new MemoryStream(128);
        write(ms);
        return ms.ToArray();
    }

    private static void WriteVarintField(MemoryStream ms, int fieldNumber, long value)
    {
        WriteVarint(ms, (ulong)((fieldNumber << 3) | 0)); // wire type 0 = varint
        WriteVarint(ms, unchecked((ulong)value));
    }

    private static void WriteString(MemoryStream ms, int fieldNumber, string value)
    {
        WriteBytes(ms, fieldNumber, Encoding.UTF8.GetBytes(value));
    }

    private static void WriteBytes(MemoryStream ms, int fieldNumber, byte[] data)
    {
        WriteVarint(ms, (ulong)((fieldNumber << 3) | 2)); // wire type 2 = length-delimited
        WriteVarint(ms, (ulong)data.Length);
        ms.Write(data, 0, data.Length);
    }

    private static void WriteVarint(MemoryStream ms, ulong value)
    {
        while (value >= 0x80)
        {
            ms.WriteByte((byte)((value & 0x7F) | 0x80));
            value >>= 7;
        }
        ms.WriteByte((byte)value);
    }
}
