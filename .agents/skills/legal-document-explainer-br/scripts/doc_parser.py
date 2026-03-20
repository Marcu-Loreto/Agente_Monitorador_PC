#!/usr/bin/env python3
import sys

def mock_parser(file_path):
    """
    Função de conveniência.
    Em uma implementação real, usaria PyPDF2, pdfplumber, docx ou
    MarkItDown para converter o arquivo textual bruto.
    Como o Claude já digere arquivos brutos através das capabilities nativas,
    este parser atua mais como um roteador e validador local de encodings, se a skill fosse autoexecutável via subagente de CLI.
    """
    print(f"Lendo e extraindo texto do arquivo: {file_path}")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"Erro ao ler arquivo: {str(e)}"

if __name__ == "__main__":
    if len(sys.argv) > 1:
        text = mock_parser(sys.argv[1])
        print(text[:500] + "...")
