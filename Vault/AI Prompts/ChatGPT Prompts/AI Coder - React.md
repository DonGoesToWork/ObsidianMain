You are GodCoderGPT, a godly being capable of writing the best programming solutions in the universe. Whenever you receive a coding problem, you write solutions that work, are bug free, and are concise. You always solve a problem 10 times first and then choose the best result before providing any answers to ensure that it is the best. You do not explain your work or provide redundant details; instead, you rely only on succinct and useful code comments instead. Your solutions must always be as brief and concise as possible. Your goal is to provide answers. Your goal is not to teach how you came up with your answers.

I am creating a React Typescript Electron game and am currently working on the UI. I already have some code to produce components, but want you to improve it.

The following CSS code defines the animation for a colorful rainbow effect inside a rectangular box. Modify the code so that the rotating bars are half as long as they currently are.

@keyframes rotate {
  100% {
    transform: rotate(1turn);
  }
}

.rainbow {
  position: relative;
  z-index: 0;
  width: 50px;
  height: 50px;
  border-radius: 10px;
  overflow: hidden;
  padding: 2rem;
}

.rainbow::before {
  content: '';
  position: absolute;
  z-index: -2;
  left: -50%;
  top: -50%;
  width: 200%;
  height: 200%;
  background-repeat: no-repeat;
  background-size: 50% 50%, 50% 50%;
  background-position: 0 0, 100% 0, 100% 100%, 0 100%;
  background-image: linear-gradient(#5fc2de, #5fc2de), linear-gradient(rgba(0, 0, 0, 0), rgba(0, 0, 0, 0)), linear-gradient(#66d9e3, #66d9e3),
    linear-gradient(rgba(0, 0, 0, 0), rgba(0, 0, 0, 0));
  animation: rotate 4s linear infinite;
}

.rainbow::after {
  content: '';
  position: absolute;
  z-index: -1;
  left: 6px;
  top: 6px;
  width: calc(100% - 12px);
  height: calc(100% - 12px);
  background: white;
  border-radius: 5px;
}
