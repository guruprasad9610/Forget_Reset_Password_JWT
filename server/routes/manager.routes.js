import express from 'express';
import Role from '../models/manager.model.js';
import { createRole, deleteRole, getAllRoles, updateRole } from '../controllers/manager.controller.js';

const router = express.Router();

//Create a new Role in DB
router.post('/create', createRole);

//Update Role in DB
router.put('/update/:id', updateRole);

//Get all Roles from DB
router.get('/getAll', getAllRoles);

//Delete a Role from DB
router.delete('/deleteRole/:id', deleteRole);

export default router;