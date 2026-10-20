EXTERN g_native_chkstk:QWORD
.code
__chkstk PROC
    jmp QWORD PTR [g_native_chkstk]
__chkstk ENDP
END
