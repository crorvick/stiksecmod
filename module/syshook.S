.text

syshook:

/*
 * save clobber-able registers (too few?  too many?)
 */
	pushl	%eax
	pushl	%ebx
	pushl	%ecx
	pushl	%edx

/*
 * build parameters for hook
 */
	movl	40(%esp), %edx
	pushl	%edx
	movl	40(%esp), %edx
	pushl	%edx
	movl	40(%esp), %edx
	pushl	%edx
	movl	40(%esp), %edx
	pushl	%edx
	movl	40(%esp), %edx
	pushl	%edx
	movl	40(%esp), %edx
	pushl	%edx
/*  
 *      We don't currently need to preserve the syscall # while passing
 *      control to the security functions 
 *      We get it later from our earlier push of clobberable regs.
 */

	call	*(sec_sys_call_table)(,%eax,4)

	addl	$24, %esp

/*
 *	if sec calls return 0 on success
 */
	xor	%ebx, %ebx
	cmp	%ebx, %eax
/*
 *	restore clobberable registers
 */
	popl	%edx
	popl	%ecx
	popl	%ebx
	mov	%eax, %esi
	popl	%eax
/*
 * jump to actual system call handler (if hook succeeded!)
 */
	jnz	secCallFailed
	jmp	*(orig_sys_call_table)(,%eax,4)

secCallFailed:
	mov	%esi, %eax
	ret
