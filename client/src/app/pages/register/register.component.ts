import { Component, OnInit, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { confirmPasswordValidator } from 'src/app/validators/confirm-password.validators';
import { AuthService } from '../../services/auth.service';
import { Router, RouterModule } from '@angular/router';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule, RouterModule],
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.scss']
})
export default class RegisterComponent implements OnInit
{
  fb = inject(FormBuilder);
  authService = inject(AuthService);
  router = inject(Router);

  registerForm !: FormGroup;

  ngOnInit(): void
  {
    this.registerForm = this.fb.group(
    {
    firstName:['', Validators.required],
    lastName:['', Validators.required],
    userName: ['', Validators.required],
    email: ['', Validators.compose([Validators.required, Validators.email])],
    password: ['', Validators.required],
    confirmPassword: ['', Validators.required]
    },
    {
      validators : confirmPasswordValidator('password', 'confirmPassword')
    }
    );
  }

  register()
  {
    // delete this.registerForm.value.confirmPassword;
    console.log(this.registerForm.value);
    this.authService.registerService(this.registerForm.value)
    .subscribe({
      next:(res) => {
        alert("User Registered Successfully !!!");
        this.registerForm.reset();
        this.router.navigate(['login']);
      },
      error:(err) => {
        console.log(err);
      }
    });
  }

}
